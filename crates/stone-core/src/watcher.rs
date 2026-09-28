//! File watcher with a settle window and echo suppression.
//!
//! - Detect: notify watcher → queue → wait for 1–2 s of quiet (absorbs
//!   editors that save via temp file + rename).
//! - Echo suppression: paths the engine itself just wrote are hashed and
//!   recorded; an event whose file hash matches the recorded write is skipped.

use crate::paths;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

/// One settled change to a vault-relative path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultChange {
    Modified(String),
    Removed(String),
    /// (from, to)
    Renamed(String, String),
}

pub struct VaultWatcher {
    _watcher: RecommendedWatcher,
    rx: Receiver<notify::Result<Event>>,
    /// Pending events: path → (kind, last_event_time).
    pending: HashMap<String, (EventKind, Instant)>,
    /// Recent renames seen inside the settle window.
    renames: Vec<(String, String, Instant)>,
    settle: Duration,
    /// Echo suppression: path → blake3 hex the engine wrote recently.
    echo: HashMap<String, (String, Instant)>,
    echo_ttl: Duration,
}

impl VaultWatcher {
    /// Watch `root` recursively. `settle` is the quiet window (spec: 1–2 s).
    pub fn new(root: &std::path::Path, settle: Duration) -> notify::Result<Self> {
        let (tx, rx) = channel();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = tx.send(res);
            },
            Config::default(),
        )?;
        watcher.watch(root, RecursiveMode::Recursive)?;
        Ok(Self {
            _watcher: watcher,
            rx,
            pending: HashMap::new(),
            renames: Vec::new(),
            settle,
            echo: HashMap::new(),
            echo_ttl: Duration::from_secs(30),
        })
    }

    /// Record an engine write for echo suppression.
    pub fn record_write(&mut self, rel: &str, content_hash: &str) {
        self.echo.insert(
            paths::normalize_rel(rel),
            (content_hash.to_string(), Instant::now()),
        );
    }

    /// Drain pending raw events into the settle buffer.
    fn pump(&mut self, vault_root: &std::path::Path) {
        while let Ok(res) = self.rx.try_recv() {
            let Ok(ev) = res else { continue };
            match ev.kind {
                EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) => {
                    for p in &ev.paths {
                        if let Some(rel) = paths::rel_from_abs(vault_root, p) {
                            self.pending
                                .insert(rel, (ev.kind.clone(), Instant::now()));
                        }
                    }
                }
                _ => {}
            }
            // notify gives RenameMode::Both pairs as Modify(Name) events on some
            // platforms; detect renames by pairing Remove+Create of same size
            // — done in `drain` via event bookkeeping below.
            if let EventKind::Modify(notify::event::ModifyKind::Name(mode)) = ev.kind.clone() {
                use notify::event::RenameMode;
                for p in &ev.paths {
                    if let Some(rel) = paths::rel_from_abs(vault_root, p) {
                        match mode {
                            RenameMode::From => {
                                self.renames.push((rel, String::new(), Instant::now()));
                            }
                            RenameMode::To => {
                                // pair with the most recent dangling From
                                if let Some(last) =
                                    self.renames.iter_mut().rev().find(|r| r.1.is_empty())
                                {
                                    last.1 = rel;
                                } else {
                                    self.renames.push((String::new(), rel, Instant::now()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Block up to `timeout` for the next settled change; returns the batch of
    /// changes after the settle window closes. Returns empty on timeout.
    pub fn next_batch(
        &mut self,
        vault_root: &std::path::Path,
        timeout: Duration,
    ) -> Vec<VaultChange> {
        let deadline = Instant::now() + timeout;
        loop {
            self.pump(vault_root);
            if self.pending.is_empty() && self.renames.is_empty() {
                let now = Instant::now();
                if now >= deadline {
                    return Vec::new();
                }
                match self.rx.recv_timeout(deadline - now) {
                    Ok(res) => {
                        if let Ok(ev) = res {
                            self.handle_event(vault_root, ev);
                        }
                    }
                    Err(_) => return Vec::new(),
                }
                continue;
            }
            // pending non-empty: wait for settle
            let oldest = self
                .pending
                .values()
                .map(|(_, t)| *t)
                .min()
                .unwrap_or_else(Instant::now);
            let fire_at = oldest + self.settle;
            let now = Instant::now();
            let fire_renames: Vec<String> = self
                .renames
                .iter()
                .filter(|(_, _, t)| *t + self.settle <= now)
                .flat_map(|(f, t, _)| [f.clone(), t.clone()])
                .collect();
            let _ = fire_renames;
            if now >= fire_at {
                return self.flush(vault_root);
            }
            let sleep_for = (fire_at - now).min(Duration::from_millis(50));
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1));
            match self.rx.recv_timeout(sleep_for.min(remaining)) {
                Ok(res) => {
                    if let Ok(ev) = res {
                        self.handle_event(vault_root, ev);
                    }
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return self.flush(vault_root);
            }
        }
    }

    fn handle_event(&mut self, vault_root: &std::path::Path, ev: Event) {
        match ev.kind {
            EventKind::Modify(notify::event::ModifyKind::Name(mode)) => {
                use notify::event::RenameMode;
                for p in &ev.paths {
                    if let Some(rel) = paths::rel_from_abs(vault_root, p) {
                        match mode {
                            RenameMode::From => {
                                self.renames.push((rel, String::new(), Instant::now()));
                            }
                            RenameMode::To => {
                                if let Some(last) =
                                    self.renames.iter_mut().rev().find(|r| r.1.is_empty())
                                {
                                    last.1 = rel;
                                } else {
                                    self.renames.push((String::new(), rel, Instant::now()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {
                for p in ev.paths {
                    if let Some(rel) = paths::rel_from_abs(vault_root, &p) {
                        self.pending.insert(rel, (ev.kind.clone(), Instant::now()));
                    }
                }
            }
        }
    }

    /// Convert settled pending events into `VaultChange`s, applying echo
    /// suppression against recorded engine writes.
    fn flush(&mut self, vault_root: &std::path::Path) -> Vec<VaultChange> {
        let mut out: Vec<VaultChange> = Vec::new();
        let pending = std::mem::take(&mut self.pending);
        let renames = std::mem::take(&mut self.renames);
        // full rename pairs first
        for (from, to, _) in &renames {
            if !from.is_empty() && !to.is_empty() {
                out.push(VaultChange::Renamed(from.clone(), to.clone()));
            }
        }
        let renamed_from: std::collections::HashSet<String> = out
            .iter()
            .filter_map(|c| match c {
                VaultChange::Renamed(f, _) => Some(f.clone()),
                _ => None,
            })
            .collect();
        let renamed_to: std::collections::HashSet<String> = out
            .iter()
            .filter_map(|c| match c {
                VaultChange::Renamed(_, t) => Some(t.clone()),
                _ => None,
            })
            .collect();
        for (rel, (kind, _)) in pending {
            if renamed_from.contains(&rel) || renamed_to.contains(&rel) {
                continue;
            }
            // echo suppression: if we recently wrote this exact hash, skip
            let abs = paths::abs_from_rel(vault_root, &rel);
            match kind {
                EventKind::Remove(_) => {
                    out.push(VaultChange::Removed(rel));
                }
                _ => {
                    if let Ok(bytes) = std::fs::read(&abs) {
                        let h = blake3::hash(&bytes).to_hex().to_string();
                        if let Some((wh, when)) = self.echo.get(&rel) {
                            if *wh == h && when.elapsed() < self.echo_ttl {
                                continue;
                            }
                        }
                        out.push(VaultChange::Modified(rel));
                    } else {
                        out.push(VaultChange::Removed(rel));
                    }
                }
            }
        }
        out
    }
}
