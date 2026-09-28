//! stone-sim — deterministic multi-device simulation for the sync engine.
//!
//! Spawns a real `stone-server` (in-process axum, ephemeral port, tempdir) and
//! N vault directories, each with a real Engine + SyncAgent. A seeded RNG
//! drives a schedule of note creates/edits/renames/deletes and syncs with
//! simulated offline windows. Assertions:
//!
//! - zero lost edits: after convergence, the *multiset* of file contents is
//!   identical across devices (a losing side of a true conflict lands as a
//!   ` (conflict …)` copy on every device, so nothing vanishes);
//! - no pending entries left on any device;
//! - identical file-name sets across devices;
//! - determinism: same seed → same final vault fingerprint.
//!
//! Time does not need mocking: correctness comes from hashes and base
//! versions, never clocks (spec: "never trust clocks").

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use stone_core::config;
use stone_core::engine::Engine;
use stone_core::error::{Result, StoneError};
use stone_core::paths;
use stone_core::sync::SyncAgent;

pub struct Device {
    pub name: String,
    pub root: PathBuf,
    pub engine: Engine,
    pub agent: SyncAgent,
    pub online: bool,
}

pub struct SimReport {
    /// path → set of contents across devices (len 1 = converged).
    pub divergent: BTreeMap<String, usize>,
    pub total_files: usize,
    pub pending_left: usize,
    pub fingerprints: Vec<String>,
}

pub struct Sim {
    pub server_url: String,
    pub devices: Vec<Device>,
    pub rng: ChaCha8Rng,
    _dirs: Vec<tempfile::TempDir>,
    /// Runtime the in-process server runs on; kept alive for the Sim's life.
    _rt: tokio::runtime::Runtime,
    /// Recent sync errors for diagnostics.
    pub errors: Vec<String>,
    /// Op history for diagnostics.
    pub log: Vec<String>,
}

const WORDS: &[&str] = &[
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi",
];

fn note_seed(i: usize, device: &str) -> String {
    format!(
        "---\nid: note-{i}\ntags: [sim]\n---\n# Note {i}\n\nstart\n\n## journal\n"
    )
    .to_string()
        + &format!("created by {device}\n")
}

impl Sim {
    /// Spin up a server and `n` joined devices.
    ///
    /// Synchronous: SyncAgent calls are reqwest-blocking, so the caller must
    /// NOT be inside a tokio runtime context. The server lives on a runtime
    /// owned by the returned Sim.
    pub fn start(seed: u64, n: usize) -> Result<Self> {
        let rng = ChaCha8Rng::seed_from_u64(seed);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(StoneError::Io)?;

        // server on ephemeral port
        let data_dir = tempfile::tempdir()?;
        let data_path = data_dir.path().to_path_buf();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .map_err(StoneError::Io)?;
        let port = listener.local_addr().map_err(StoneError::Io)?.port();
        rt.spawn(async move {
            let _ = stone_server::serve(listener, data_path).await;
        });
        let server_url = format!("http://127.0.0.1:{port}");

        let mut dirs: Vec<tempfile::TempDir> = vec![data_dir];
        let mut devices = Vec::new();
        let mut vault_id = String::new();
        for i in 0..n {
            let dir = tempfile::tempdir()?;
            let root = dir.path().to_path_buf();
            config::init_vault(&root, Some(&format!("dev{i}")))?;
            if i == 0 {
                let out = SyncAgent::setup(&root, &server_url, "dev0", "pw")?;
                vault_id = out.vault_id;
            }
            dirs.push(dir);
            devices.push((root, format!("dev{i}")));
        }
        // join devices 1..n via invite from dev0
        let mut joined = Vec::new();
        for (i, (root, name)) in devices.iter().enumerate() {
            if i == 0 {
                continue;
            }
            let inviter = SyncAgent::open(&devices[0].0)?;
            let (_id, token) = inviter.invite(name)?;
            SyncAgent::join(root, &server_url, &vault_id, &token, name, "pw")?;
            joined.push(());
        }
        let _ = joined;
        let mut devs = Vec::new();
        for (root, name) in devices {
            let engine = Engine::open(&root)?;
            let agent = SyncAgent::open(&root)?;
            devs.push(Device {
                name,
                root,
                engine,
                agent,
                online: true,
            });
        }
        Ok(Sim {
            server_url,
            devices: devs,
            rng,
            _dirs: dirs,
            _rt: rt,
            errors: Vec::new(),
            log: Vec::new(),
        })
    }

    /// One random operation step on a random device.
    pub fn step(&mut self, notes: usize) {
        let d = self.rng.random_range(0..self.devices.len());
        let roll = self.rng.random_range(0..100);
        let dev = &mut self.devices[d];
        match roll {
            // create a note (bounded population so edits collide productively)
            0..=14 => {
                let i = self.rng.random_range(0..notes.max(4));
                let rel = format!("sim/n{i}.md");
                if !dev.root.join("sim").join(format!("n{i}.md")).exists() {
                    let _ = dev.engine.write_file(&rel, note_seed(i, &dev.name).as_bytes());
                    self.log.push(format!("{} create {}", dev.name, rel));
                }
            }
            // append — biased to distinct sections per device to make merges
            // usually clean, with occasional same-region collisions
            15..=44 => {
                let i = self.rng.random_range(0..notes.max(4));
                let rel = format!("sim/n{i}.md");
                let p = dev.root.join("sim").join(format!("n{i}.md"));
                if p.exists() {
                    let line = format!(
                        "\n{} {}-{:03}",
                        WORDS[self.rng.random_range(0..WORDS.len())],
                        dev.name,
                        self.rng.random_range(0..1000)
                    );
                    let _ = dev.engine.append(&rel, &line);
                }
            }
            // edit: replace a word in the note
            45..=59 => {
                let i = self.rng.random_range(0..notes.max(4));
                let rel = format!("sim/n{i}.md");
                if dev.root.join("sim").join(format!("n{i}.md")).exists() {
                    let _ = dev.engine.edit(
                        &rel,
                        "start",
                        &format!("edited-{}", WORDS[self.rng.random_range(0..WORDS.len())]),
                        false,
                    );
                }
            }
            // rename with backlink rewriting off the golden path (rare)
            60..=64 => {
                let i = self.rng.random_range(0..notes.max(4));
                let rel = format!("sim/n{i}.md");
                let newn = format!("sim/n{i}-r{}.md", d);
                if dev.root.join("sim").join(format!("n{i}.md")).exists()
                    && !dev.root.join("sim").join(format!("n{i}-r{}.md", d)).exists()
                {
                    let _ = dev.engine.rename_file(&rel, &newn);
                    self.log.push(format!("{} rename {}->{}", dev.name, rel, newn));
                }
            }
            // trash (rare)
            65..=69 => {
                let i = self.rng.random_range(0..notes.max(4));
                let rel = format!("sim/n{i}.md");
                if dev.root.join("sim").join(format!("n{i}.md")).exists() {
                    let _ = dev.engine.trash_file(&rel);
                    self.log.push(format!("{} trash {}", dev.name, rel));
                }
            }
            // offline window toggle
            70..=79 => {
                dev.online = !dev.online;
            }
            // sync
            _ => {
                if dev.online {
                    if let Err(e) = dev.agent.sync_now(&dev.engine, false) {
                        self.errors.push(format!("{}: {e}", dev.name));
                    }
                }
            }
        }
    }

    /// Bring every device online and sync until no device has pending work
    /// and two consecutive rounds change nothing on the server.
    pub fn converge(&mut self) {
        for _round in 0..40 {
            for dev in &mut self.devices {
                dev.online = true;
                if let Err(e) = dev.agent.sync_now(&dev.engine, true) {
                    self.errors.push(format!("{}: {e}", dev.name));
                }
            }
            if self.devices.iter().all(|d| {
                d.engine
                    .journal()
                    .pending()
                    .map(|p| p.is_empty())
                    .unwrap_or(true)
            }) {
                // one more round so pulled merges land everywhere
                for dev in &mut self.devices {
                    if let Err(e) = dev.agent.sync_now(&dev.engine, true) {
                        self.errors.push(format!("{}: {e}", dev.name));
                    }
                }
                break;
            }
        }
    }

    /// The vault's synced files (rel → content bytes), excluding `.stone/trash`
    /// and other engine-internal paths.
    fn snapshot(dev: &Device) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        if e.file_name() != ".stone" {
                            walk(root, &p, out);
                        }
                    } else {
                        let rel = p
                            .strip_prefix(root)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/");
                        if paths::syncable(&rel) {
                            out.insert(rel, std::fs::read(&p).unwrap_or_default());
                        }
                    }
                }
            }
        }
        walk(&dev.root, &dev.root, &mut out);
        out
    }

    /// Multiset of file contents across the vault — the zero-lost-edits check.
    fn content_multiset(dev: &Device) -> Vec<u64> {
        let mut v: Vec<u64> = Self::snapshot(dev)
            .values()
            .map(|b| blake3::hash(b).as_bytes()[..8].iter().fold(0u64, |a, &x| (a << 8) | x as u64))
            .collect();
        v.sort();
        v
    }

    /// Deterministic fingerprint of a device (paths + hashes).
    fn fingerprint(dev: &Device) -> String {
        let snap = Self::snapshot(dev);
        let mut h = blake3::Hasher::new();
        for (p, b) in &snap {
            h.update(p.as_bytes());
            h.update(b);
        }
        h.finalize().to_hex().to_string()
    }

    /// Assert convergence + zero lost edits.
    pub fn verify(&self) -> Result<SimReport> {
        let manifest = self
            .devices
            .first()
            .and_then(|d| d.agent.fetch_manifest().ok());
        let head_of = |path: &str, dev: &Device| -> String {
            let pid = dev.agent.key.path_id(path);
            manifest
                .as_ref()
                .and_then(|m| {
                    m.files
                        .iter()
                        .find(|f| f.path_id == pid)
                        .map(|f| format!("head={} del={}", &f.head_version[..8], f.deleted))
                })
                .unwrap_or_else(|| "no-head".to_string())
        };
        let snaps: Vec<BTreeMap<String, Vec<u8>>> =
            self.devices.iter().map(Self::snapshot).collect();
        let d0 = &snaps[0];
        let mut divergent: BTreeMap<String, usize> = BTreeMap::new();
        let mut names_equal = true;
        for s in &snaps[1..] {
            // path sets must match exactly (conflict copies included)
            let a: std::collections::BTreeSet<_> = d0.keys().collect();
            let b: std::collections::BTreeSet<_> = s.keys().collect();
            if a != b {
                names_equal = false;
                for k in a.symmetric_difference(&b) {
                    let all: Vec<String> = self
                        .devices
                        .iter()
                        .enumerate()
                        .map(|(i, d)| {
                            let has = snaps[i].contains_key(*k);
                            let _ = i;
                            let j = d
                                .engine
                                .journal()
                                .get(k)
                                .ok()
                                .flatten()
                                .map(|e| {
                                    format!(
                                        "v={:?} del={} h={:.8}",
                                        e.version_id, e.deleted, e.hash
                                    )
                                })
                                .unwrap_or_else(|| "nojournal".to_string());
                            format!("{}:{}{}", d.name, if has { "F" } else { "-" }, j)
                        })
                        .collect();
                    let srv = head_of(k, &self.devices[0]);
                    divergent.insert(format!("pathset:{k} devs {all:?} srv[{srv}]"), 1);
                }
            }
            for (p, bytes) in d0 {
                if let Some(other) = s.get(p) {
                    if other != bytes {
                        divergent.insert(p.clone(), 2);
                    }
                }
            }
        }
        // zero lost edits: content multisets equal
        let ms0 = Self::content_multiset(&self.devices[0]);
        let mut lost_edits = false;
        for d in &self.devices[1..] {
            if Self::content_multiset(d) != ms0 {
                lost_edits = true;
            }
        }
        let pending_left: usize = self
            .devices
            .iter()
            .map(|d| {
                d.engine
                    .journal()
                    .pending()
                    .map(|p| p.len())
                    .unwrap_or(0)
            })
            .sum();
        let fingerprints = self.devices.iter().map(Self::fingerprint).collect();
        let report = SimReport {
            divergent: divergent.clone(),
            total_files: d0.len(),
            pending_left,
            fingerprints,
        };
        if pending_left > 0 {
            let tail: Vec<&str> = self
                .errors
                .iter()
                .rev()
                .take(5)
                .map(String::as_str)
                .collect();
            let mut detail = Vec::new();
            for d in &self.devices {
                if let Ok(p) = d.engine.journal().pending() {
                    for e in p {
                        detail.push(format!(
                            "{}:{:?}:{}->{:?}",
                            d.name, e.kind, e.path, e.old_path
                        ));
                    }
                }
            }
            return Err(StoneError::Message(format!(
                "sim: {pending_left} pending entries left after converge; pending: {detail:?}; errors: {tail:?}"
            )));
        }
        if lost_edits {
            let diff: Vec<&String> = divergent.keys().take(10).collect();
            // recent ops touching the divergent paths, for the failure report
            let stems: Vec<String> = divergent
                .keys()
                .take(4)
                .map(|k| {
                    k.trim_start_matches("pathset:")
                        .split(' ')
                        .next()
                        .unwrap_or(k)
                        .trim_end_matches(".md")
                        .to_string()
                })
                .collect();
            let ops: Vec<&String> = self
                .log
                .iter()
                .filter(|l| stems.iter().any(|s| l.contains(s)))
                .rev()
                .take(20)
                .collect();
            let errs: Vec<&String> = self.errors.iter().rev().take(4).collect();
            return Err(StoneError::Message(format!(
                "sim: content multiset differs — an edit was lost; divergent: {diff:?}; ops: {ops:?}; errs: {errs:?}"
            )));
        }
        if !names_equal {
            return Err(StoneError::Message(
                "sim: path sets differ across devices".into(),
            ));
        }
        Ok(report)
    }
}
