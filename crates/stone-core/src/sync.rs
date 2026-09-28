//! Sync protocol (client side) + the sync agent.
//!
//! Wire contract (v1, self-defined — the spec's Contracts tab wasn't included):
//!
//! - `POST /v1/vaults` `{vault_id, device_name, device_token_hash, wrapped_key_b64,
//!   argon2_salt_b64, recovery_wrapped_b64, recovery_salt_b64}` → `{device_id}`.
//!   Creates the vault; the client mints the `stn_dev_*` bearer and sends its
//!   hash, so the server never holds an usable token.
//! - `POST /v1/vaults/{v}/devices` `{device_name, device_token_hash}` (bearer)
//!   → `{device_id}`. The inviting device mints the token; the joining device
//!   gets it out-of-band plus the vault password.
//! - `GET  /v1/vaults/{v}/keys` (bearer) → wrapped key material (for joins).
//! - `PUT  /v1/vaults/{v}/blobs/{id}` body=ciphertext → `{ok, exists}` (idempotent).
//! - `GET  /v1/vaults/{v}/blobs/{id}` → ciphertext bytes.
//! - `GET  /v1/vaults/{v}/manifest` → `{seq, files:[{path_id, head_version, deleted}]}`.
//! - `GET  /v1/vaults/{v}/changes?since=N` → `{latest_seq, changes:[WireChange]}`.
//! - `POST /v1/vaults/{v}/commits` `CommitRequest` → `{seq}` or `409` with heads.
//! - `GET  /v1/vaults/{v}/history/{path_id}` → `[{version_id, seq, kind, ts}]`.
//! - `GET  /v1/vaults/{v}/versions/{version_id}` → `VersionData`.
//! - `GET  /v1/ws?vault={v}&seq={n}` → WebSocket announcing `{seq}` on commit.
//!
//! Encryption: every blob is `nonce(24) || XChaCha20-Poly1305(chunk)`.
//! enc_meta decrypts to `{path, size, mtime, old_path?}` (JSON).
//! path_id = keyed BLAKE3(normalized path); blob_id = keyed BLAKE3(plaintext).

use crate::config::{self, SyncConfig};
use crate::crypto::VaultKey;
use crate::engine::Engine;
use crate::error::{Result, StoneError};
use crate::journal::{JournalEntry, PendingKind};
use crate::merge::{self, MergeOutcome};
use crate::paths;
use crate::{chunk, journal};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

// ============================= wire types =============================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Put,
    Delete,
    Rename,
}

/// One file change inside a commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeEntry {
    pub path_id: String,
    /// version_id the client based this change on (None = file didn't exist).
    pub base_version: Option<String>,
    /// New version id (uuid). For delete: tombstone marker version.
    pub version_id: String,
    pub kind: ChangeKind,
    /// Ordered chunk blob ids (empty for delete).
    pub blob_ids: Vec<String>,
    /// Encrypted metadata blob (b64): {path, size, mtime, old_path?}.
    pub enc_meta: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitRequest {
    pub device_id: String,
    pub changes: Vec<ChangeEntry>,
}

/// One committed change as the server reports it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireChange {
    pub seq: i64,
    pub ts: i64,
    pub device_id: String,
    pub path_id: String,
    pub version_id: String,
    pub kind: ChangeKind,
    pub blob_ids: Vec<String>,
    pub enc_meta: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangesResponse {
    pub latest_seq: i64,
    pub changes: Vec<WireChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    pub path_id: String,
    pub head_version: String,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub seq: i64,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionData {
    pub version_id: String,
    pub path_id: String,
    pub seq: i64,
    pub kind: ChangeKind,
    pub blob_ids: Vec<String>,
    pub enc_meta: String,
    pub ts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub version_id: String,
    pub seq: i64,
    pub kind: ChangeKind,
    pub ts: i64,
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub merged: usize,
    pub conflict_copies: usize,
    pub seq: i64,
    pub took_ms: u64,
}

/// Decrypted metadata payload stored in `enc_meta`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMeta {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    #[serde(default)]
    pub old_path: Option<String>,
}

// ============================= agent =============================

pub struct SyncAgent {
    pub root: std::path::PathBuf,
    pub key: VaultKey,
    pub cfg: SyncConfig,
    pub device_id: String,
    http: reqwest::blocking::Client,
}

impl SyncAgent {
    /// Open the sync agent for a vault (requires `stone sync setup` first).
    pub fn open(root: &Path) -> Result<Self> {
        let cfg = config::load_sync_config(root);
        if cfg.server_url.is_none() || cfg.vault_id.is_none() {
            return Err(StoneError::SyncNotConfigured);
        }
        let key_b64 = cfg
            .vault_key_b64
            .clone()
            .ok_or(StoneError::SyncNotConfigured)?;
        let key = VaultKey::from_b64(&key_b64)?;
        let device_id = cfg
            .device_id
            .clone()
            .or_else(|| cfg.device_name.clone())
            .unwrap_or_else(|| "device".to_string());
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(StoneError::Http)?;
        Ok(Self {
            root: root.to_path_buf(),
            key,
            cfg,
            device_id,
            http,
        })
    }

    fn url(&self, path: &str) -> String {
        let base = self.cfg.server_url.clone().unwrap_or_default();
        format!("{}/{}{}", base.trim_end_matches('/'), "v1", path)
    }

    fn vault_url(&self, suffix: &str) -> String {
        self.url(&format!(
            "/vaults/{}{}",
            self.cfg.vault_id.clone().unwrap_or_default(),
            suffix
        ))
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.cfg.device_token.clone().unwrap_or_default())
    }

    /// `stone sync setup` — create vault + first device on a server.
    /// `password` wraps the vault key; returns the printed recovery key to show once.
    pub fn setup(root: &Path, server_url: &str, device_name: &str, password: &str) -> Result<SetupOut> {
        let key = VaultKey::generate();
        let vault_id = key.vault_id();
        let (wrapped_b64, salt_b64) = key.wrap(password)?;
        let (recovery_key, recovery_raw) = VaultKey::generate_recovery_key();
        let (recovery_wrapped_b64, recovery_salt_b64) = {
            // wrap vault key under the recovery key (hex of raw bytes as "password")
            let rk_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(recovery_raw);
            key.wrap(&rk_b64)?
        };
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(StoneError::Http)?;
        let device_token = crate::crypto::new_device_token();
        let base = server_url.trim_end_matches('/');
        let resp = http
            .post(format!("{base}/v1/vaults"))
            .json(&serde_json::json!({
                "vault_id": vault_id,
                "device_name": device_name,
                "device_token_hash": crate::crypto::token_hash(&device_token),
                "wrapped_key_b64": wrapped_b64,
                "argon2_salt_b64": salt_b64,
                "recovery_wrapped_b64": recovery_wrapped_b64,
                "recovery_salt_b64": recovery_salt_b64,
            }))
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!(
                "sync setup failed: HTTP {}",
                resp.status()
            )));
        }
        let out: serde_json::Value = resp.json().map_err(StoneError::Http)?;
        let device_id = out
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("dev-1")
            .to_string();

        let cfg = SyncConfig {
            server_url: Some(base.to_string()),
            vault_id: Some(vault_id),
            device_token: Some(device_token),
            device_id: Some(device_id.clone()),
            device_name: Some(device_name.to_string()),
            vault_key_b64: Some(key.to_b64()),
            wrapped_key_b64: Some(wrapped_b64),
            argon2_salt_b64: Some(salt_b64),
        };
        config::save_sync_config(root, &cfg)?;
        Ok(SetupOut {
            device_id,
            recovery_key,
            vault_id: cfg.vault_id.clone().unwrap(),
        })
    }

    /// `stone sync invite` — mint a device token for a second machine.
    /// The printed token goes (out-of-band) to the new device together with
    /// the vault password; the server only ever stores its hash.
    pub fn invite(&self, device_name: &str) -> Result<(String, String)> {
        let token = crate::crypto::new_device_token();
        let url = self.vault_url("/devices");
        let resp = self
            .http
            .post(&url)
            .header("authorization", self.bearer())
            .json(&serde_json::json!({
                "device_name": device_name,
                "device_token_hash": crate::crypto::token_hash(&token),
            }))
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!("invite: HTTP {}", resp.status())));
        }
        let out: serde_json::Value = resp.json().map_err(StoneError::Http)?;
        let device_id = out
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("dev")
            .to_string();
        Ok((device_id, token))
    }

    /// `stone sync join` — onboard this device with an invite token + password.
    pub fn join(
        root: &Path,
        server_url: &str,
        vault_id: &str,
        device_token: &str,
        device_name: &str,
        password: &str,
    ) -> Result<()> {
        let base = server_url.trim_end_matches('/');
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(StoneError::Http)?;
        let url = format!("{base}/v1/vaults/{vault_id}/keys");
        let resp = http
            .get(&url)
            .header("authorization", format!("Bearer {device_token}"))
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!(
                "join: HTTP {} (bad invite token?)",
                resp.status()
            )));
        }
        let out: serde_json::Value = resp.json().map_err(StoneError::Http)?;
        let get = |k: &str| -> Result<String> {
            out.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| StoneError::Message(format!("join: server missing {k}")))
        };
        let wrapped = get("wrapped_key_b64")?;
        let salt = get("argon2_salt_b64")?;
        let key = VaultKey::unwrap(&wrapped, &salt, password)
            .map_err(|_| StoneError::InvalidInput("wrong vault password".into()))?;
        let device_id = out
            .get("device_id")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let cfg = SyncConfig {
            server_url: Some(base.to_string()),
            vault_id: Some(vault_id.to_string()),
            device_token: Some(device_token.to_string()),
            device_id,
            device_name: Some(device_name.to_string()),
            vault_key_b64: Some(key.to_b64()),
            wrapped_key_b64: Some(wrapped),
            argon2_salt_b64: Some(salt),
        };
        config::save_sync_config(root, &cfg)?;
        Ok(())
    }

    /// Decrypt a FileMeta.
    fn decrypt_meta(&self, enc_meta: &str) -> Result<FileMeta> {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bytes = b64
            .decode(enc_meta)
            .map_err(|e| StoneError::Crypto(format!("meta b64: {e}")))?;
        let pt = self.key.decrypt(&bytes)?;
        serde_json::from_slice(&pt).map_err(StoneError::Json)
    }

    fn encrypt_meta(&self, meta: &FileMeta) -> Result<String> {
        let pt = serde_json::to_vec(meta)?;
        let ct = self.key.encrypt(&pt);
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ct))
    }

    /// Upload a file's chunks; returns ordered blob ids.
    fn upload_blobs(&self, data: &[u8]) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        for c in chunk::chunk(data) {
            let plain = &data[c.offset..c.offset + c.length];
            let id = self.key.blob_id(plain);
            let ct = self.key.encrypt(plain);
            let url = self.vault_url(&format!("/blobs/{id}"));
            let resp = self
                .http
                .put(&url)
                .header("authorization", self.bearer())
                .body(ct)
                .send()
                .map_err(StoneError::Http)?;
            if !resp.status().is_success() {
                return Err(StoneError::Message(format!(
                    "blob upload {id}: HTTP {}",
                    resp.status()
                )));
            }
            ids.push(id);
        }
        Ok(ids)
    }

    /// Download + decrypt + reassemble a version's content.
    pub fn download_version(&self, v: &VersionData) -> Result<Vec<u8>> {
        let mut parts = Vec::new();
        for id in &v.blob_ids {
            let url = self.vault_url(&format!("/blobs/{id}"));
            let resp = self
                .http
                .get(&url)
                .header("authorization", self.bearer())
                .send()
                .map_err(StoneError::Http)?;
            if !resp.status().is_success() {
                return Err(StoneError::Message(format!(
                    "blob download {id}: HTTP {}",
                    resp.status()
                )));
            }
            let ct = resp.bytes().map_err(StoneError::Http)?;
            parts.push(self.key.decrypt(&ct)?);
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Ok(chunk::assemble(&refs))
    }

    /// Fetch remote changes since a seq.
    pub fn fetch_changes(&self, since: i64) -> Result<ChangesResponse> {
        let url = self.vault_url(&format!("/changes?since={since}"));
        let resp = self
            .http
            .get(&url)
            .header("authorization", self.bearer())
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!(
                "changes fetch: HTTP {}",
                resp.status()
            )));
        }
        resp.json().map_err(StoneError::Http)
    }

    pub fn fetch_manifest(&self) -> Result<Manifest> {
        let url = self.vault_url("/manifest");
        let resp = self
            .http
            .get(&url)
            .header("authorization", self.bearer())
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!(
                "manifest: HTTP {}",
                resp.status()
            )));
        }
        resp.json().map_err(StoneError::Http)
    }

    fn fetch_history(&self, path_id: &str) -> Result<Vec<HistoryEntry>> {
        let url = self.vault_url(&format!("/history/{path_id}"));
        let resp = self
            .http
            .get(&url)
            .header("authorization", self.bearer())
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!("history: HTTP {}", resp.status())));
        }
        resp.json().map_err(StoneError::Http)
    }

    fn fetch_version(&self, version_id: &str) -> Result<VersionData> {
        let url = self.vault_url(&format!("/versions/{version_id}"));
        let resp = self
            .http
            .get(&url)
            .header("authorization", self.bearer())
            .send()
            .map_err(StoneError::Http)?;
        if !resp.status().is_success() {
            return Err(StoneError::Message(format!("version: HTTP {}", resp.status())));
        }
        resp.json().map_err(StoneError::Http)
    }

    /// Commit a batch of changes (CAS per path on base_version).
    pub fn commit(&self, req: &CommitRequest) -> Result<i64> {
        let url = self.vault_url("/commits");
        let resp = self
            .http
            .post(&url)
            .header("authorization", self.bearer())
            .json(req)
            .send()
            .map_err(StoneError::Http)?;
        if resp.status().as_u16() == 409 {
            let body = resp.text().unwrap_or_default();
            return Err(StoneError::SyncRejected(body));
        }
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().unwrap_or_default();
            return Err(StoneError::Message(format!(
                "commit: HTTP {status}: {body}"
            )));
        }
        let out: serde_json::Value = resp.json().map_err(StoneError::Http)?;
        Ok(out.get("seq").and_then(|v| v.as_i64()).unwrap_or(0))
    }

    /// The full sync cycle: pull + apply remote, then push local dirty set.
    /// On CAS rejection: pull, merge, retry (bounded).
    pub fn sync_now(&self, engine: &Engine, force: bool) -> Result<SyncReport> {
        let started = Instant::now();
        let journal = engine.journal();
        let mut pushed = 0usize;
        let mut pulled = 0usize;
        let mut merged = 0usize;
        let mut conflicts = 0usize;
        let mut last_reject = String::new();

        // hold the per-vault-per-device sync lock for the whole cycle
        let lock_path = engine.local.sync_lock();
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)?;
        let mut rwlock = fd_lock::RwLock::new(lock_file);
        let _guard = rwlock.try_write().map_err(|_| StoneError::SyncLockHeld)?;

        for attempt in 0..5 {
            // ---- pull + apply ----
            let since = journal.last_seq()?;
            let resp = self.fetch_changes(since)?;
            let mut changes_by_path: BTreeMap<String, Vec<WireChange>> = BTreeMap::new();
            let mut max_seq = since;
            for c in &resp.changes {
                max_seq = max_seq.max(c.seq);
                changes_by_path
                    .entry(c.path_id.clone())
                    .or_default()
                    .push(c.clone());
            }
            // count incoming deletes for the mass-delete guard
            let mut deletes = 0usize;
            let total_paths = journal.all_paths()?.len().max(1);
            for list in changes_by_path.values() {
                if let Some(last) = list.iter().max_by_key(|c| c.seq) {
                    if matches!(last.kind, ChangeKind::Delete) {
                        deletes += 1;
                    }
                }
            }
            // mass-delete guard: >10% of files or >50 files pauses and asks
            if !force && deletes > 0 && (deletes > 50 || deletes as f64 > total_paths as f64 * 0.10) {
                return Err(StoneError::MassDeleteGuard(
                    deletes,
                    deletes as f64 / total_paths as f64 * 100.0,
                ));
            }
            // Apply in strict global seq order. Grouping by path loses causal
            // ordering across paths (a Rename@seq14 of n0 must apply before a
            // Put@seq54 that recreates n0); pull-window boundaries must not
            // change the outcome.
            let mut ordered: Vec<WireChange> =
                changes_by_path.into_values().flatten().collect();
            ordered.sort_by_key(|c| c.seq);
            for change in ordered {
                let (p, m, c) = self.apply_remote(engine, journal, &change)?;
                pulled += p;
                merged += m;
                conflicts += c;
            }
            journal.set_last_seq(max_seq)?;

            // ---- push pending/dirty ----
            let batch = self.collect_local_changes(engine, journal)?;
            if batch.is_empty() {
                let _ = attempt;
                return Ok(SyncReport {
                    pushed,
                    pulled,
                    merged,
                    conflict_copies: conflicts,
                    seq: max_seq,
                    took_ms: started.elapsed().as_millis() as u64,
                });
            }
            let req = CommitRequest {
                device_id: self.device_id.clone(),
                changes: batch,
            };
            match self.commit(&req) {
                Ok(seq) => {
                    if std::env::var_os("STONE_SYNC_TRACE").is_some() {
                        let kinds: Vec<String> = req
                            .changes
                            .iter()
                            .map(|c| format!("{:?}:{:.8}", c.kind, c.path_id))
                            .collect();
                        eprintln!("[{}] commit ok seq={} [{}]", self.device_id, seq, kinds.join(","));
                    }
                    pushed += req_changes_len(&req);
                    // journal: advance each path's base to the committed version.
                    // Do NOT advance last_seq to our commit seq: foreign commits
                    // interleave inside our commit's seq range on the server and
                    // must still be delivered by the next pull. Own changes echo
                    // back and re-apply as no-ops (local == remote).
                    for e in &req.changes {
                        let meta = self.decrypt_meta(&e.enc_meta)?;
                        self.record_synced(journal, &meta.path, e)?;
                    }
                    return Ok(SyncReport {
                        pushed,
                        pulled,
                        merged,
                        conflict_copies: conflicts,
                        seq,
                        took_ms: started.elapsed().as_millis() as u64,
                    });
                }
                Err(StoneError::SyncRejected(body)) => {
                    last_reject = body;
                    // Our journal's view of server heads is approximate; a head
                    // may have moved after our last pull (e.g. a delete landed
                    // under a tracking row we materialized locally). Ask the
                    // server for the true heads and retry this batch directly.
                    if let Ok(man) = self.fetch_manifest() {
                        let heads: std::collections::HashMap<&str, Option<String>> = man
                            .files
                            .iter()
                            .map(|f| {
                                (
                                    f.path_id.as_str(),
                                    if f.deleted {
                                        None
                                    } else {
                                        Some(f.head_version.clone())
                                    },
                                )
                            })
                            .collect();
                        let mut retry = req.changes.clone();
                        let mut repaired = false;
                        for c in &mut retry {
                            let true_base = heads
                                .get(c.path_id.as_str())
                                .cloned()
                                .unwrap_or(None);
                            if true_base != c.base_version {
                                c.base_version = true_base;
                                repaired = true;
                            }
                        }
                        if repaired {
                            let req2 = CommitRequest {
                                device_id: self.device_id.clone(),
                                changes: retry,
                            };
                            match self.commit(&req2) {
                                Ok(seq) => {
                                    pushed += req2.changes.len();
                                    for e in &req2.changes {
                                        let meta = self.decrypt_meta(&e.enc_meta)?;
                                        self.record_synced(journal, &meta.path, e)?;
                                    }
                                    return Ok(SyncReport {
                                        pushed,
                                        pulled,
                                        merged,
                                        conflict_copies: conflicts,
                                        seq,
                                        took_ms: started.elapsed().as_millis() as u64,
                                    });
                                }
                                Err(StoneError::SyncRejected(b2)) => {
                                    last_reject = b2;
                                }
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(StoneError::Conflict(format!(
            "sync commit kept being rejected after retries; last: {last_reject}"
        )))
    }

    /// Apply one remote change to disk + journal (crash-safe: write file via
    /// temp+rename, then journal update; ordering lets re-hash recovery work).
    fn apply_remote(
        &self,
        engine: &Engine,
        journal: &journal::Journal,
        change: &WireChange,
    ) -> Result<(usize, usize, usize)> {
        let meta = self.decrypt_meta(&change.enc_meta)?;
        let path = meta.path.clone();
        if std::env::var_os("STONE_SYNC_TRACE").is_some() {
            eprintln!(
                "[{}] apply seq={} {:?} {} old={:?}",
                self.device_id, change.seq, change.kind, path, meta.old_path
            );
        }
        let mut applied = 0usize;
        let mut merged = 0usize;
        let mut conflicts = 0usize;
        match change.kind {
            ChangeKind::Delete => {
                let abs = paths::abs_from_rel(&engine.root, &path);
                let e = journal.get(&path)?;
                let local_dirty = match (abs.exists(), &e) {
                    (true, Some(entry)) => {
                        let cur = fs::read(&abs).unwrap_or_default();
                        blake3::hash(&cur).to_hex().to_string() != entry.hash
                    }
                    _ => false,
                };
                if abs.exists() {
                    if !local_dirty {
                        fs::remove_file(&abs).ok();
                        let _ = journal.remove(&path);
                        applied += 1;
                    } else {
                        // Local edits win over the remote delete. The server's
                        // head for this path is now `deleted`, so CAS expects
                        // base=None on the next push — clear the version_id,
                        // but keep the OLD synced hash so the scanner still
                        // sees the file as dirty and re-pushes it.
                        let cur = fs::read(&abs).unwrap_or_default();
                        journal.upsert(&JournalEntry {
                            path: path.clone(),
                            path_id: change.path_id.clone(),
                            version_id: None,
                            seq: change.seq,
                            hash: e.map(|je| je.hash).unwrap_or_default(),
                            base: cur,
                            deleted: false,
                        })?;
                    }
                } else {
                    // file already gone locally — still drop the journal row so
                    // a recreated file isn't pinned to a dead version (its head
                    // is now deleted on the server → CAS base must be None).
                    let _ = journal.remove(&path);
                    if std::env::var_os("STONE_SYNC_TRACE").is_some() {
                        eprintln!("[{}] journal.remove {} (delete, file absent)", self.device_id, path);
                    }
                }
            }
            ChangeKind::Rename => {
                let old_path = meta.old_path.clone().unwrap_or_default();
                let new_path = path.clone();
                let version = self.fetch_version(&change.version_id)?;
                let remote = self.download_version(&version)?;
                let abs_new = paths::abs_from_rel(&engine.root, &new_path);
                let abs_old = paths::abs_from_rel(&engine.root, &old_path);
                if let Some(parent) = abs_new.parent() {
                    fs::create_dir_all(parent)?;
                }
                let local_bytes = fs::read(&abs_old).ok();
                let base = journal.get(&old_path)?.map(|e| e.base).unwrap_or_default();
                match local_bytes {
                    None => {
                        // simple rename
                        atomic_write(&abs_new, &remote)?;
                        let hash = blake3::hash(&remote).to_hex().to_string();
                        journal.upsert(&JournalEntry {
                            path: new_path.clone(),
                            path_id: change.path_id.clone(),
                            version_id: Some(change.version_id.clone()),
                            seq: change.seq,
                            hash,
                            base: remote,
                            deleted: false,
                        })?;
                        journal.remove(&old_path)?;
                        applied += 1;
                    }
                    Some(local) => {
                        // merge content under the new name
                        let (content, did_merge, did_conflict) =
                            self.merge_into(&engine.root, &new_path, &base, &local, &remote)?;
                        atomic_write(&abs_new, &content)?;
                        if abs_old != abs_new && abs_old.exists() {
                            fs::remove_file(&abs_old).ok();
                        }
                        let hash = blake3::hash(&remote).to_hex().to_string();
                        journal.upsert(&JournalEntry {
                            path: new_path.clone(),
                            path_id: change.path_id.clone(),
                            version_id: Some(change.version_id.clone()),
                            seq: change.seq,
                            hash,
                            base: remote,
                            deleted: false,
                        })?;
                        journal.remove(&old_path)?;
                        applied += 1;
                        merged += did_merge;
                        conflicts += did_conflict;
                    }
                }
            }
            ChangeKind::Put => {
                let version = self.fetch_version(&change.version_id)?;
                let remote = self.download_version(&version)?;
                let abs = paths::abs_from_rel(&engine.root, &path);
                // remote edited a path we renamed away before syncing:
                // merge the remote content into the new file instead of
                // resurrecting the old path locally.
                if !abs.exists() {
                    let redirect = journal.pending()?.into_iter().find(|p| {
                        matches!(p.kind, PendingKind::Rename)
                            && p.old_path.as_deref() == Some(path.as_str())
                            && paths::abs_from_rel(&engine.root, &p.path).exists()
                    });
                    if let Some(rp) = redirect {
                        let new_abs = paths::abs_from_rel(&engine.root, &rp.path);
                        let local = fs::read(&new_abs).unwrap_or_default();
                        let base = journal
                            .get(&rp.path)?
                            .map(|e| e.base)
                            .unwrap_or_default();
                        let (content, dm, dc) =
                            self.merge_into(&engine.root, &rp.path, &base, &local, &remote)?;
                        atomic_write(&new_abs, &content)?;
                        // track old's new head (path-id-keyed row, no file):
                        // the delete we emit uses it as the CAS base
                        journal.upsert(&JournalEntry {
                            path: path.clone(),
                            path_id: change.path_id.clone(),
                            version_id: Some(change.version_id.clone()),
                            seq: change.seq,
                            hash: blake3::hash(&remote).to_hex().to_string(),
                            base: remote,
                            deleted: false,
                        })?;
                        applied += 1;
                        merged += dm;
                        conflicts += dc;
                        return Ok((applied, merged, conflicts));
                    }
                }
                if let Some(parent) = abs.parent() {
                    fs::create_dir_all(parent)?;
                }
                let entry = journal.get(&path)?;
                let local_bytes = fs::read(&abs).unwrap_or_default();
                let base = entry.clone().map(|e| e.base).unwrap_or_default();
                let synced_hash = entry.map(|e| e.hash).unwrap_or_default();
                let local_hash = blake3::hash(&local_bytes).to_hex().to_string();
                if !abs.exists() || local_hash == synced_hash {
                    // no local divergence — just write remote
                    atomic_write(&abs, &remote)?;
                    let hash = blake3::hash(&remote).to_hex().to_string();
                    journal.upsert(&JournalEntry {
                        path: path.clone(),
                        path_id: change.path_id.clone(),
                        version_id: Some(change.version_id.clone()),
                        seq: change.seq,
                        hash,
                        base: remote,
                        deleted: false,
                    })?;
                    applied += 1;
                } else {
                    let (content, did_merge, did_conflict) =
                        self.merge_into(&engine.root, &path, &base, &local_bytes, &remote)?;
                    atomic_write(&abs, &content)?;
                    let hash = blake3::hash(&remote).to_hex().to_string();
                    journal.upsert(&JournalEntry {
                        path: path.clone(),
                        path_id: change.path_id.clone(),
                        version_id: Some(change.version_id.clone()),
                        seq: change.seq,
                        hash,
                        base: remote,
                        deleted: false,
                    })?;
                    applied += 1;
                    merged += did_merge;
                    conflicts += did_conflict;
                }
            }
        }
        Ok((applied, merged, conflicts))
    }

    /// Merge base/ours/theirs for `path`; on conflict write the conflict copy.
    /// Returns (content to keep at path, did_merge, did_conflict).
    fn merge_into(
        &self,
        root: &Path,
        path: &str,
        base: &[u8],
        ours: &[u8],
        theirs: &[u8],
    ) -> Result<(Vec<u8>, usize, usize)> {
        if ours == base || ours == theirs {
            return Ok((theirs.to_vec(), 0, 0));
        }
        if theirs == base {
            return Ok((ours.to_vec(), 0, 0));
        }
        match merge::merge_file(path, base, ours, theirs) {
            MergeOutcome::Clean(bytes) => Ok((bytes, 1, 0)),
            MergeOutcome::Conflicted { merged, remote } => {
                let cname = merge::conflict_name(
                    path,
                    self.cfg
                        .device_name
                        .clone()
                        .unwrap_or_else(|| "remote".into())
                        .as_str(),
                    chrono::Utc::now(),
                );
                let cabs = paths::abs_from_rel(root, &cname);
                if let Some(parent) = cabs.parent() {
                    fs::create_dir_all(parent)?;
                }
                atomic_write(&cabs, &remote)?;
                Ok((merged, 1, 1))
            }
        }
    }

    /// Local files differing from the journal's last-synced hash → change batch.
    /// At most one change per path_id — a second entry in the same commit would
    /// CAS-fail against the head the first one just wrote.
    fn collect_local_changes(&self, engine: &Engine, journal: &journal::Journal) -> Result<Vec<ChangeEntry>> {
        let mut out: Vec<ChangeEntry> = Vec::new();
        let mut seen_pid: std::collections::HashSet<String> = std::collections::HashSet::new();
        macro_rules! emit {
            ($e:expr) => {{
                let c = $e?;
                if seen_pid.insert(c.path_id.clone()) {
                    out.push(c);
                }
            }};
        }
        // 1) pending queue (engine writes — includes renames/deletes)
        let pending = journal.pending()?;
        let mut covered: std::collections::HashSet<String> = std::collections::HashSet::new();
        for p in &pending {
            covered.insert(p.path.clone());
            match p.kind {
                PendingKind::Delete => {
                    let entry = journal.get(&p.path)?;
                    emit!(self.change_delete(entry, &p.path));
                }
                PendingKind::Rename => {
                    let old = p.old_path.clone().unwrap_or_default();
                    // head[old] as we know it: a remote edit may have
                    // re-materialized `old` (apply_remote Put recreated the
                    // row at `old`); else the row migrated to `new` carries
                    // the last-synced version of `old`.
                    let old_entry = journal
                        .get(&old)
                        .ok()
                        .flatten()
                        .or_else(|| journal.get(&p.path).ok().flatten());
                    if paths::abs_from_rel(&engine.root, &p.path).exists() {
                        emit!(self.change_put(engine, &p.path, None, Some(&old)));
                        if let Some(e) = old_entry {
                            emit!(self.delete_for_old(e, &old));
                        }
                    } else {
                        match old_entry {
                            Some(e) if !e.deleted => {
                                emit!(self.delete_for_old(e, &old))
                            }
                            _ => journal.clear_pending(&p.path)?,
                        }
                    }
                }
                PendingKind::Upsert => {
                    let entry = journal.get(&p.path)?;
                    if paths::abs_from_rel(&engine.root, &p.path).exists() {
                        emit!(self.change_put(engine, &p.path, entry.as_ref(), None));
                    } else if let Some(e) = entry {
                        // vanished before push and was synced once → delete
                        emit!(self.change_delete(Some(e), &p.path));
                    } else {
                        // never synced, already gone — nothing to send
                        journal.clear_pending(&p.path)?;
                    }
                }
            }
        }
        // 2) scanner fallback for out-of-band edits (vim/git): hash vs journal
        for (rel, meta) in engine.scan_files(false)? {
            if covered.contains(&rel) {
                continue;
            }
            if !paths::syncable(&rel) {
                continue;
            }
            let entry = journal.get(&rel)?;
            match entry {
                Some(e) => {
                    if e.hash != meta.hash && !meta.hash.is_empty() {
                        emit!(self.change_put(engine, &rel, Some(&e), None));
                    }
                }
                None => {
                    // new file never journaled
                    emit!(self.change_put(engine, &rel, None, None));
                }
            }
        }
        // 3) deletes discovered by scan: journaled but file gone
        let disk: std::collections::HashSet<String> =
            engine.scan_files(false)?.into_iter().map(|(r, _)| r).collect();
        for e in journal.all_paths()? {
            if covered.contains(&e.path) || e.deleted {
                continue;
            }
            if !disk.contains(&e.path) {
                emit!(self.change_delete(Some(e.clone()), &e.path));
            }
        }
        Ok(out)
    }

    fn change_put(
        &self,
        engine: &Engine,
        rel: &str,
        base_entry: Option<&JournalEntry>,
        old_path: Option<&str>,
    ) -> Result<ChangeEntry> {
        let abs = paths::abs_from_rel(&engine.root, rel);
        let bytes = fs::read(&abs)?;
        let blob_ids = self.upload_blobs(&bytes)?;
        let meta = FileMeta {
            path: rel.to_string(),
            size: bytes.len() as u64,
            mtime: fs::metadata(&abs)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            old_path: old_path.map(String::from),
        };
        let version_id = uuid::Uuid::new_v4().to_string();
        let path_id = self.key.path_id(rel);
        Ok(ChangeEntry {
            // CAS base must be the head for THIS path_id: a deleted head or a
            // row whose path_id differs (rename-migrated) both mean None.
            base_version: base_entry.and_then(|e| {
                if e.deleted || e.path_id != path_id {
                    None
                } else {
                    e.version_id.clone()
                }
            }),
            path_id,
            version_id,
            kind: if old_path.is_some() {
                ChangeKind::Rename
            } else {
                ChangeKind::Put
            },
            blob_ids,
            enc_meta: self.encrypt_meta(&meta)?,
        })
    }

    fn change_delete(&self, entry: Option<JournalEntry>, rel: &str) -> Result<ChangeEntry> {
        let meta = FileMeta {
            path: rel.to_string(),
            size: 0,
            mtime: 0,
            old_path: None,
        };
        let path_id = self.key.path_id(rel);
        Ok(ChangeEntry {
            base_version: entry.and_then(|e| {
                if e.deleted || e.path_id != path_id {
                    None
                } else {
                    e.version_id.clone()
                }
            }),
            path_id,
            version_id: uuid::Uuid::new_v4().to_string(),
            kind: ChangeKind::Delete,
            blob_ids: vec![],
            enc_meta: self.encrypt_meta(&meta)?,
        })
    }

    /// Delete `old` using `e`'s version_id as base — used for renames, where
    /// `e` is the journal row that was migrated to the new path (its
    /// version_id is head[old]; its path_id is old's).
    fn delete_for_old(&self, e: JournalEntry, old: &str) -> Result<ChangeEntry> {
        let path_id = self.key.path_id(old);
        let meta = FileMeta {
            path: old.to_string(),
            size: 0,
            mtime: 0,
            old_path: None,
        };
        Ok(ChangeEntry {
            path_id,
            base_version: if e.deleted { None } else { e.version_id },
            version_id: uuid::Uuid::new_v4().to_string(),
            kind: ChangeKind::Delete,
            blob_ids: vec![],
            enc_meta: self.encrypt_meta(&meta)?,
        })
    }

    /// Record a committed version in the journal (clears pending).
    fn record_synced(
        &self,
        journal: &journal::Journal,
        path: &str,
        e: &ChangeEntry,
    ) -> Result<()> {
        let path = paths::normalize_rel(path);
        let abs = paths::abs_from_rel(&self.root, &path);
        let bytes = fs::read(&abs).unwrap_or_default();
        let deleted = matches!(e.kind, ChangeKind::Delete);
        if deleted && abs.exists() {
            let prev_hash = journal
                .get(&path)?
                .map(|je| je.hash)
                .unwrap_or_default();
            let cur_hash = blake3::hash(&bytes).to_hex().to_string();
            if cur_hash == prev_hash {
                // file still matches what we committed as deleted — drop it
                let _ = fs::remove_file(&abs);
            } else {
                // edited locally between collect and commit: keep the file and
                // re-push it as a fresh upsert (head is now deleted → base None)
                journal.queue_pending(&path, PendingKind::Upsert, None)?;
            }
        }
        journal.upsert(&JournalEntry {
            path: path.clone(),
            path_id: e.path_id.clone(),
            version_id: Some(e.version_id.clone()),
            seq: 0, // caller bumps via set_last_seq
            hash: if deleted {
                String::new()
            } else {
                blake3::hash(&bytes).to_hex().to_string()
            },
            base: bytes,
            deleted,
        })?;
        journal.clear_pending(&path)?;
        Ok(())
    }

    /// `stone sync conflicts` — local conflict copies.
    pub fn conflicts(&self, engine: &Engine) -> Result<Vec<String>> {
        let mut out = Vec::new();
        for (rel, _) in engine.scan_files(false)? {
            if crate::links::basename(&rel).contains(" (conflict ") {
                out.push(rel);
            }
        }
        Ok(out)
    }

    /// `stone sync history <note>` — version list from the server.
    pub fn history(&self, engine: &Engine, note: &str) -> Result<Vec<HistoryEntry>> {
        let path = engine.resolve_note(note)?;
        self.fetch_history(&self.key.path_id(&path))
    }

    /// `stone sync restore <note> --version N` — write that version's content.
    pub fn restore(&self, engine: &Engine, note: &str, version_id: &str) -> Result<String> {
        let path = engine.resolve_note(note)?;
        let v = self.fetch_version(version_id)?;
        let bytes = self.download_version(&v)?;
        let abs = paths::abs_from_rel(&engine.root, &path);
        atomic_write(&abs, &bytes)?;
        engine.journal().queue_pending(&path, PendingKind::Upsert, None)?;
        Ok(path)
    }
}

impl ChangeKind {
    pub fn kind_is_delete(&self) -> bool {
        matches!(self, ChangeKind::Delete)
    }
}

fn req_changes_len(req: &CommitRequest) -> usize {
    req.changes.len()
}

/// Atomic file write: temp sibling + rename.
pub fn atomic_write(abs: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = abs.with_extension("tmp-stone");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, abs)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct SetupOut {
    pub device_id: String,
    /// Shown once — the owner must save it.
    pub recovery_key: String,
    pub vault_id: String,
}

/// Status for `stone sync status`.
#[derive(Debug, Serialize)]
pub struct SyncStatus {
    pub configured: bool,
    pub server_url: Option<String>,
    pub vault_id: Option<String>,
    pub device_name: Option<String>,
    pub last_seq: i64,
    pub pending: usize,
}

pub fn status(engine: &Engine) -> Result<SyncStatus> {
    let cfg = config::load_sync_config(&engine.root);
    let j = engine.journal();
    Ok(SyncStatus {
        configured: cfg.server_url.is_some(),
        server_url: cfg.server_url,
        vault_id: cfg.vault_id,
        device_name: cfg.device_name,
        last_seq: j.last_seq()?,
        pending: j.pending()?.len(),
    })
}
