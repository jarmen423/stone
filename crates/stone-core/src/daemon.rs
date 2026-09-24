//! The Stone daemon: one process per vault holding the index open, watching
//! files, and running the sync agent. The CLI forwards commands to it over a
//! loopback JSON-RPC socket (port published in the cache dir) so the index
//! stays warm and writes stay coordinated. Without a daemon the CLI opens
//! the vault directly — both paths go through the same Engine.
//!
//! Wire protocol: one JSON object per line over TCP on 127.0.0.1.
//!   request:  {"id": n, "command": "search", "args": {...}}
//!   response: {"id": n, "ok": true, "data": {...}}  or  {"ok": false, "error": {"code", "message"}}

use crate::engine::Engine;
use crate::error::{Result, StoneError};
use crate::paths;
use crate::sync::SyncAgent;
use crate::watcher::{VaultChange, VaultWatcher};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonInfo {
    pub port: u16,
    pub pid: u32,
    pub vault: String,
}

/// Where the daemon's port file lives for a vault.
fn port_file(root: &Path) -> std::path::PathBuf {
    crate::config::vault_local_dir(root).join("daemon.port")
}

/// Read a live daemon's info, or None when no daemon answers.
pub fn daemon_info(root: &Path) -> Option<DaemonInfo> {
    let p = port_file(root);
    let info: DaemonInfo = serde_json::from_str(&fs::read_to_string(&p).ok()?).ok()?;
    // verify liveness with a ping
    let resp = forward(root, &serde_json::json!({"id": 0, "command": "ping", "args": {}}), Duration::from_millis(300));
    match resp {
        Some(v) if v.get("ok").and_then(|x| x.as_bool()) == Some(true) => Some(info),
        _ => None,
    }
}

/// Forward one JSON request to the running daemon. None = no daemon.
pub fn forward(root: &Path, req: &serde_json::Value, timeout: Duration) -> Option<serde_json::Value> {
    let info_raw = fs::read_to_string(port_file(root)).ok()?;
    let info: DaemonInfo = serde_json::from_str(&info_raw).ok()?;
    let mut stream = TcpStream::connect(("127.0.0.1", info.port)).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let line = serde_json::to_string(req).ok()? + "\n";
    stream.write_all(line.as_bytes()).ok()?;
    let mut reader = BufReader::new(stream);
    let mut buf = String::new();
    reader.read_line(&mut buf).ok()?;
    serde_json::from_str(&buf).ok()
}

/// Ask the daemon to stop (removes the port file + terminates).
pub fn stop(root: &Path) -> bool {
    let resp = forward(
        root,
        &serde_json::json!({"id": 0, "command": "shutdown", "args": {}}),
        Duration::from_millis(500),
    );
    let _ = fs::remove_file(port_file(root));
    resp.is_some()
}

/// Daemon main loop. Blocks; returns when shutdown is requested.
pub fn run(root: &Path, sync_every_secs: u64, shutdown: Arc<AtomicBool>) -> Result<()> {
    let engine = Engine::open(root)?;
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let info = DaemonInfo {
        port,
        pid: std::process::id(),
        vault: root.display().to_string(),
    };
    if let Some(parent) = port_file(root).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(port_file(root), serde_json::to_string(&info)?)?;

    // watcher for index freshness + sync triggering
    let mut watcher = VaultWatcher::new(root, Duration::from_millis(1500))
        .map_err(|e| StoneError::Message(format!("watcher: {e}")))?;
    let mut last_sync = std::time::Instant::now() - Duration::from_secs(3600);
    let mut dirty_since: Option<std::time::Instant> = None;

    tracing::info!("stone daemon listening on 127.0.0.1:{port}");
    while !shutdown.load(Ordering::Relaxed) {
        // drain watcher into index/pending
        let batch = watcher.next_batch(root, Duration::from_millis(250));
        if !batch.is_empty() {
            if let Ok(idx) = engine.index() {
                for ch in &batch {
                    match ch {
                        VaultChange::Modified(rel) => {
                            if paths_indexable(rel) {
                                if let Ok(text) = fs::read_to_string(
                                    paths::abs_from_rel(root, rel),
                                ) {
                                    let _ = engine_refresh_one(&engine, &idx, rel, &text);
                                }
                            }
                        }
                        VaultChange::Removed(rel) => {
                            let _ = idx.remove_note(rel);
                        }
                        VaultChange::Renamed(f, t) => {
                            let _ = idx.remove_note(f);
                            if paths_indexable(t) {
                                if let Ok(text) =
                                    fs::read_to_string(paths::abs_from_rel(root, t))
                                {
                                    let _ = engine_refresh_one(&engine, &idx, t, &text);
                                }
                            }
                        }
                    }
                }
            }
            dirty_since = Some(std::time::Instant::now());
        }

        // sync after settle: dirty + quiet for 1.5s, or every sync_every_secs
        let should_sync = match dirty_since {
            Some(t) => t.elapsed() >= Duration::from_millis(1500),
            None => sync_every_secs > 0 && last_sync.elapsed() >= Duration::from_secs(sync_every_secs),
        };
        if should_sync {
            if let Ok(agent) = SyncAgent::open(root) {
                if let Err(e) = agent.sync_now(&engine, false) {
                    tracing::warn!("sync: {e}");
                } else {
                    dirty_since = None;
                }
            }
            last_sync = std::time::Instant::now();
        }

        // serve commands
        match listener.accept() {
            Ok((stream, _)) => {
                let shutdown_flag = shutdown.clone();
                let root_owned = root.to_path_buf();
                std::thread::spawn(move || {
                    let _ = handle_conn(stream, &root_owned, shutdown_flag);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }
    }
    let _ = fs::remove_file(port_file(root));
    Ok(())
}

fn paths_indexable(rel: &str) -> bool {
    crate::paths::indexable(rel)
}

fn engine_refresh_one(engine: &Engine, idx: &crate::index::Index, rel: &str, text: &str) -> Result<()> {
    let vl = engine.vault_links_full(idx)?;
    idx.update_note(rel, text, chrono::Utc::now().timestamp(), &|t| {
        vl.resolve(t).ok().flatten()
    })
}

fn handle_conn(
    stream: TcpStream,
    root: &Path,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        let req: serde_json::Value = match serde_json::from_str(line.trim()) {
            Ok(v) => v,
            Err(e) => {
                let resp = serde_json::json!({"ok": false, "error": {"code": "bad_request", "message": e.to_string()}});
                writer.write_all((serde_json::to_string(&resp)? + "\n").as_bytes())?;
                line.clear();
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(serde_json::json!(0));
        let command = req.get("command").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let args = req.get("args").cloned().unwrap_or(serde_json::json!({}));
        let resp = if command == "ping" {
            serde_json::json!({"id": id, "ok": true, "data": {"pong": true}})
        } else if command == "shutdown" {
            shutdown.store(true, Ordering::Relaxed);
            serde_json::json!({"id": id, "ok": true, "data": {"stopping": true}})
        } else {
            match crate::registry::invoke_path(root, &command, &args) {
                Ok(data) => serde_json::json!({"id": id, "ok": true, "data": data}),
                Err(e) => serde_json::json!({"id": id, "ok": false, "error": {"code": e.code(), "message": e.to_string()}}),
            }
        };
        writer.write_all((serde_json::to_string(&resp)? + "\n").as_bytes())?;
        line.clear();
        if command == "shutdown" {
            break;
        }
    }
    Ok(())
}

/// Write a platform service definition so the daemon autostarts.
/// - Linux: systemd user unit `~/.config/systemd/user/stone.service`
/// - macOS: `~/Library/LaunchAgents/dev.stone.daemon.plist`
/// - Windows: prints a `schtasks` command (registry run key equivalent).
pub fn install_service(root: &Path) -> Result<String> {
    let exe = std::env::current_exe()?;
    let exe = exe.display().to_string();
    let vault = root.display().to_string();
    #[cfg(target_os = "linux")]
    {
        let dir = directories::BaseDirs::new()
            .map(|d| d.config_dir().join("systemd/user"))
            .unwrap_or_else(|| std::path::PathBuf::from("~/.config/systemd/user"));
        fs::create_dir_all(&dir)?;
        let unit = format!(
            "[Unit]\nDescription=Stone vault daemon\n\n[Service]\nExecStart={exe} daemon run --vault \"{vault}\"\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n"
        );
        let p = dir.join("stone.service");
        fs::write(&p, unit)?;
        return Ok(format!(
            "wrote {} — enable with: systemctl --user enable --now stone.service",
            p.display()
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let dir = directories::BaseDirs::new()
            .map(|d| d.home_dir().join("Library/LaunchAgents"))
            .unwrap_or_default();
        fs::create_dir_all(&dir)?;
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.stone.daemon</string>
<key>ProgramArguments</key><array><string>{exe}</string><string>daemon</string><string>run</string><string>--vault</string><string>{vault}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>"#
        );
        let p = dir.join("dev.stone.daemon.plist");
        fs::write(&p, plist)?;
        return Ok(format!(
            "wrote {} — load with: launchctl load {}",
            p.display(),
            p.display()
        ));
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(format!(
            "Windows service: register with\n  schtasks /create /tn StoneDaemon /sc onlogon /tr \"\\\"{exe}\\\" daemon run --vault \\\"{vault}\\\"\""
        ));
    }
    #[allow(unreachable_code)]
    Ok("unsupported platform for daemon install".to_string())
}


