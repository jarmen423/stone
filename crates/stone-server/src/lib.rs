//! stone-server — the encrypted sync server.
//!
//! It stores only ciphertext: FastCDC chunks under `<data>/blobs/<vault>/<id>`
//! and metadata in `<data>/stone.db` (SQLite WAL). The server never sees a
//! plaintext path, note, or key — `path_id`/`blob_id`/`vault_id` are keyed
//! BLAKE3 outputs and `enc_meta`/`wrapped_key` are encrypted client-side.
//!
//! API (see crates/stone-core/src/sync.rs for the client):
//!   POST   /v1/vaults                          create vault + first device
//!   POST   /v1/vaults/{v}/devices              add a device (bearer auth)
//!   GET    /v1/vaults/{v}/keys                 wrapped key material (bearer)
//!   PUT    /v1/vaults/{v}/blobs/{id}           store encrypted chunk
//!   GET    /v1/vaults/{v}/blobs/{id}           fetch encrypted chunk
//!   GET    /v1/vaults/{v}/manifest             current heads + seq
//!   GET    /v1/vaults/{v}/changes?since=N      change feed
//!   POST   /v1/vaults/{v}/commits              CAS commit (409 on stale base)
//!   GET    /v1/vaults/{v}/history/{path_id}    per-path version history
//!   GET    /v1/vaults/{v}/versions/{vid}       one version record
//!   GET    /v1/ws?vault={v}&seq={n}            live change notifications

use axum::{
    body::Bytes,
    extract::{Path as AxPath, Query, State, WebSocketUpgrade},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

pub struct App {
    db: Mutex<Connection>,
    blob_root: PathBuf,
    /// vault_id → notification channel carrying the new latest seq.
    watchers: Mutex<HashMap<String, broadcast::Sender<i64>>>,
}

#[derive(Debug)]
struct ApiErr(StatusCode, String);

impl ApiErr {
    fn bad(m: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, m.into())
    }
    fn unauth(m: impl Into<String>) -> Self {
        Self(StatusCode::UNAUTHORIZED, m.into())
    }
    fn notfound(m: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, m.into())
    }
    fn conflict(v: Value) -> Self {
        Self(StatusCode::CONFLICT, serde_json::to_string(&v).unwrap_or_default())
    }
    fn internal(e: impl std::fmt::Display) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

impl std::fmt::Display for ApiErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.0, self.1)
    }
}

impl std::error::Error for ApiErr {}

impl axum::response::IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let body = if self.0 == StatusCode::CONFLICT {
            self.1 // already a JSON body with heads
        } else {
            json!({"ok": false, "error": {"message": self.1}}).to_string()
        };
        (self.0, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

type ApiResult<T> = Result<T, ApiErr>;

// ============================ request types ============================

#[derive(Deserialize)]
struct CreateVault {
    vault_id: String,
    device_name: String,
    device_token_hash: String,
    wrapped_key_b64: String,
    argon2_salt_b64: String,
    recovery_wrapped_b64: String,
    recovery_salt_b64: String,
}

#[derive(Deserialize)]
struct AddDevice {
    device_name: String,
    device_token_hash: String,
}

#[derive(Deserialize)]
struct CommitReq {
    device_id: String,
    changes: Vec<Change>,
}

#[derive(Deserialize, Serialize, Clone)]
struct Change {
    path_id: String,
    base_version: Option<String>,
    version_id: String,
    kind: String, // put | delete | rename
    blob_ids: Vec<String>,
    enc_meta: String,
}

#[derive(Deserialize)]
struct SinceQ {
    since: Option<i64>,
}

#[derive(Deserialize)]
struct WsQ {
    vault: String,
    seq: Option<i64>,
}

// ============================ serve ============================

/// Build the axum router against a data directory.
pub fn router(data: &FsPath) -> std::io::Result<Router> {
    std::fs::create_dir_all(data.join("blobs"))?;
    let db = Connection::open(data.join("stone.db")).map_err(std::io::Error::other)?;
    init_db(&db).map_err(std::io::Error::other)?;
    let app = Arc::new(App {
        db: Mutex::new(db),
        blob_root: data.join("blobs"),
        watchers: Mutex::new(HashMap::new()),
    });
    Ok(Router::new()
        .route("/v1/vaults", post(create_vault))
        .route("/v1/vaults/{v}/devices", post(add_device))
        .route("/v1/vaults/{v}/keys", get(get_keys))
        .route("/v1/vaults/{v}/blobs/{id}", put(put_blob).get(get_blob))
        .route("/v1/vaults/{v}/manifest", get(manifest))
        .route("/v1/vaults/{v}/changes", get(changes))
        .route("/v1/vaults/{v}/commits", post(commit))
        .route("/v1/vaults/{v}/history/{path_id}", get(history))
        .route("/v1/vaults/{v}/versions/{vid}", get(version))
        .route("/v1/ws", get(ws))
        .with_state(app))
}

/// Serve on an already-bound listener (so callers can bind port 0).
pub async fn serve(listener: tokio::net::TcpListener, data: PathBuf) -> std::io::Result<()> {
    let r = router(&data)?;
    axum::serve(listener, r).await
}

fn init_db(db: &Connection) -> ApiResult<()> {
    db.pragma_update(None, "journal_mode", "WAL")
        .map_err(ApiErr::internal)?;
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS vaults(
            vault_id TEXT PRIMARY KEY,
            wrapped_key_b64 TEXT NOT NULL,
            argon2_salt_b64 TEXT NOT NULL,
            recovery_wrapped_b64 TEXT NOT NULL,
            recovery_salt_b64 TEXT NOT NULL,
            created_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices(
            device_id TEXT PRIMARY KEY,
            vault_id TEXT NOT NULL,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_ts INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS changes(
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            vault_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            version_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            blob_ids TEXT NOT NULL,
            enc_meta TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS changes_vault_seq ON changes(vault_id, seq);
        CREATE INDEX IF NOT EXISTS changes_vault_path ON changes(vault_id, path_id, seq);
        CREATE INDEX IF NOT EXISTS changes_version ON changes(vault_id, version_id);
        CREATE TABLE IF NOT EXISTS heads(
            vault_id TEXT NOT NULL,
            path_id TEXT NOT NULL,
            head_version TEXT NOT NULL,
            deleted INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            PRIMARY KEY (vault_id, path_id)
        );
        CREATE TABLE IF NOT EXISTS blobs(
            vault_id TEXT NOT NULL,
            blob_id TEXT NOT NULL,
            size INTEGER NOT NULL,
            PRIMARY KEY (vault_id, blob_id)
        );",
    )
    .map_err(ApiErr::internal)?;
    Ok(())
}

// ============================ auth ============================

/// Resolve the bearer token to (vault_id, device_id); verify it matches the
/// vault in the URL.
fn authed(app: &App, headers: &HeaderMap, vault: &str) -> ApiResult<String> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiErr::unauth("missing bearer token"))?;
    let hash = stone_core::crypto::token_hash(token);
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let row: Option<(String, String)> = db
        .query_row(
            "SELECT vault_id, device_id FROM devices WHERE token_hash=?1",
            params![hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .ok();
    match row {
        Some((v, dev)) if v == vault => Ok(dev),
        Some(_) => Err(ApiErr::unauth("device belongs to another vault")),
        None => Err(ApiErr::unauth("bad device token")),
    }
}

// ============================ handlers ============================

async fn create_vault(
    State(app): State<Arc<App>>,
    Json(req): Json<CreateVault>,
) -> ApiResult<Json<Value>> {
    let device_id = format!("dev-{}", uuid::Uuid::new_v4().simple());
    let ts = chrono::Utc::now().timestamp();
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let tx = db.unchecked_transaction().map_err(ApiErr::internal)?;
    tx.execute(
        "INSERT INTO vaults(vault_id, wrapped_key_b64, argon2_salt_b64,
            recovery_wrapped_b64, recovery_salt_b64, created_ts)
         VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            req.vault_id,
            req.wrapped_key_b64,
            req.argon2_salt_b64,
            req.recovery_wrapped_b64,
            req.recovery_salt_b64,
            ts
        ],
    )
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            ApiErr::bad("vault already exists")
        } else {
            ApiErr::internal(e)
        }
    })?;
    tx.execute(
        "INSERT INTO devices(device_id, vault_id, name, token_hash, created_ts)
         VALUES(?1,?2,?3,?4,?5)",
        params![device_id, req.vault_id, req.device_name, req.device_token_hash, ts],
    )
    .map_err(ApiErr::internal)?;
    tx.commit().map_err(ApiErr::internal)?;
    Ok(Json(json!({"ok": true, "device_id": device_id, "vault_id": req.vault_id})))
}

async fn add_device(
    State(app): State<Arc<App>>,
    AxPath(vault): AxPath<String>,
    headers: HeaderMap,
    Json(req): Json<AddDevice>,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let device_id = format!("dev-{}", uuid::Uuid::new_v4().simple());
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    db.execute(
        "INSERT INTO devices(device_id, vault_id, name, token_hash, created_ts)
         VALUES(?1,?2,?3,?4,?5)",
        params![
            device_id,
            vault,
            req.device_name,
            req.device_token_hash,
            chrono::Utc::now().timestamp()
        ],
    )
    .map_err(ApiErr::internal)?;
    Ok(Json(json!({"ok": true, "device_id": device_id})))
}

async fn get_keys(
    State(app): State<Arc<App>>,
    AxPath(vault): AxPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let dev = authed(&app, &headers, &vault)?;
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let row = db.query_row(
        "SELECT wrapped_key_b64, argon2_salt_b64, recovery_wrapped_b64, recovery_salt_b64
         FROM vaults WHERE vault_id=?1",
        params![vault],
        |r| {
            Ok(json!({
                "wrapped_key_b64": r.get::<_, String>(0)?,
                "argon2_salt_b64": r.get::<_, String>(1)?,
                "recovery_wrapped_b64": r.get::<_, String>(2)?,
                "recovery_salt_b64": r.get::<_, String>(3)?,
                "device_id": dev,
            }))
        },
    );
    match row {
        Ok(v) => Ok(Json(v)),
        Err(_) => Err(ApiErr::notfound("vault")),
    }
}

fn blob_path(app: &App, vault: &str, id: &str) -> PathBuf {
    app.blob_root.join(vault).join(id)
}

async fn put_blob(
    State(app): State<Arc<App>>,
    AxPath((vault, id)): AxPath<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let p = blob_path(&app, &vault, &id);
    let existed = p.exists();
    if !existed {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(ApiErr::internal)?;
        }
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, &body).map_err(ApiErr::internal)?;
        std::fs::rename(&tmp, &p).map_err(ApiErr::internal)?;
        let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
        db.execute(
            "INSERT OR IGNORE INTO blobs(vault_id, blob_id, size) VALUES(?1,?2,?3)",
            params![vault, id, body.len() as i64],
        )
        .map_err(ApiErr::internal)?;
    }
    Ok(Json(json!({"ok": true, "exists": existed})))
}

async fn get_blob(
    State(app): State<Arc<App>>,
    AxPath((vault, id)): AxPath<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    authed(&app, &headers, &vault)?;
    let p = blob_path(&app, &vault, &id);
    match std::fs::read(&p) {
        Ok(bytes) => Ok(([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()),
        Err(_) => Err(ApiErr::notfound("blob")),
    }
}

async fn manifest(
    State(app): State<Arc<App>>,
    AxPath(vault): AxPath<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let seq: i64 = db
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM changes WHERE vault_id=?1",
            params![vault],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let mut st = db
        .prepare("SELECT path_id, head_version, deleted FROM heads WHERE vault_id=?1")
        .map_err(ApiErr::internal)?;
    let files: Vec<Value> = st
        .query_map(params![vault], |r| {
            Ok(json!({
                "path_id": r.get::<_, String>(0)?,
                "head_version": r.get::<_, String>(1)?,
                "deleted": r.get::<_, i64>(2)? != 0,
            }))
        })
        .map_err(ApiErr::internal)?
        .collect::<Result<_, _>>()
        .map_err(ApiErr::internal)?;
    Ok(Json(json!({"seq": seq, "files": files})))
}

fn change_json(r: &rusqlite::Row) -> rusqlite::Result<Value> {
    Ok(json!({
        "seq": r.get::<_, i64>(0)?,
        "ts": r.get::<_, i64>(1)?,
        "device_id": r.get::<_, String>(2)?,
        "path_id": r.get::<_, String>(3)?,
        "version_id": r.get::<_, String>(4)?,
        "kind": r.get::<_, String>(5)?,
        "blob_ids": serde_json::from_str::<Vec<String>>(&r.get::<_, String>(6)?)
            .unwrap_or_default(),
        "enc_meta": r.get::<_, String>(7)?,
    }))
}

const CHANGE_COLS: &str = "seq, ts, device_id, path_id, version_id, kind, blob_ids, enc_meta";

async fn changes(
    State(app): State<Arc<App>>,
    AxPath(vault): AxPath<String>,
    Query(q): Query<SinceQ>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let since = q.since.unwrap_or(0);
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let mut st = db
        .prepare(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE vault_id=?1 AND seq>?2 ORDER BY seq"
        ))
        .map_err(ApiErr::internal)?;
    let rows: Vec<Value> = st
        .query_map(params![vault, since], change_json)
        .map_err(ApiErr::internal)?
        .collect::<Result<_, _>>()
        .map_err(ApiErr::internal)?;
    let latest: i64 = db
        .query_row(
            "SELECT COALESCE(MAX(seq),0) FROM changes WHERE vault_id=?1",
            params![vault],
            |r| r.get(0),
        )
        .unwrap_or(0);
    Ok(Json(json!({"latest_seq": latest, "changes": rows})))
}

async fn history(
    State(app): State<Arc<App>>,
    AxPath((vault, path_id)): AxPath<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let mut st = db
        .prepare(
            "SELECT version_id, seq, kind, ts FROM changes
             WHERE vault_id=?1 AND path_id=?2 ORDER BY seq",
        )
        .map_err(ApiErr::internal)?;
    let rows: Vec<Value> = st
        .query_map(params![vault, path_id], |r| {
            Ok(json!({
                "version_id": r.get::<_, String>(0)?,
                "seq": r.get::<_, i64>(1)?,
                "kind": r.get::<_, String>(2)?,
                "ts": r.get::<_, i64>(3)?,
            }))
        })
        .map_err(ApiErr::internal)?
        .collect::<Result<_, _>>()
        .map_err(ApiErr::internal)?;
    Ok(Json(Value::Array(rows)))
}

async fn version(
    State(app): State<Arc<App>>,
    AxPath((vault, vid)): AxPath<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authed(&app, &headers, &vault)?;
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let row = db.query_row(
        &format!("SELECT {CHANGE_COLS} FROM changes WHERE vault_id=?1 AND version_id=?2"),
        params![vault, vid],
        change_json,
    );
    match row {
        Ok(v) => {
            // expose path_id & version_id at top level to match VersionData
            Ok(Json(json!({
                "version_id": vid,
                "path_id": v["path_id"],
                "seq": v["seq"],
                "kind": v["kind"],
                "blob_ids": v["blob_ids"],
                "enc_meta": v["enc_meta"],
                "ts": v["ts"],
            })))
        }
        Err(_) => Err(ApiErr::notfound("version")),
    }
}

/// CAS commit: every change's base_version must equal the current head for
/// its path_id (None ⇔ no head / deleted head). One transaction → one seq
/// range per commit, so multi-file ops land atomically.
async fn commit(
    State(app): State<Arc<App>>,
    AxPath(vault): AxPath<String>,
    headers: HeaderMap,
    Json(req): Json<CommitReq>,
) -> ApiResult<Json<Value>> {
    let dev = authed(&app, &headers, &vault)?;
    if dev != req.device_id {
        return Err(ApiErr::unauth("device_id does not match token"));
    }
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let tx = db.unchecked_transaction().map_err(ApiErr::internal)?;

    // check every base first — reject the whole commit on any mismatch
    let mut stale: Vec<Value> = Vec::new();
    for c in &req.changes {
        let head: Option<(String, i64)> = tx
            .query_row(
                "SELECT head_version, deleted FROM heads WHERE vault_id=?1 AND path_id=?2",
                params![vault, c.path_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        let cur: Option<String> = head.and_then(|(v, d)| if d != 0 { None } else { Some(v) });
        let base = c.base_version.clone().filter(|s| !s.is_empty());
        if cur != base {
            stale.push(json!({
                "path_id": c.path_id,
                "head": cur,
            }));
        }
    }
    if !stale.is_empty() {
        return Err(ApiErr::conflict(json!({
            "ok": false, "error": {"message": "stale base"}, "stale": stale
        })));
    }

    let ts = chrono::Utc::now().timestamp();
    let mut last_seq = 0i64;
    for c in &req.changes {
        let blob_ids = serde_json::to_string(&c.blob_ids).map_err(ApiErr::internal)?;
        last_seq = tx
            .query_row(
                &format!(
                    "INSERT INTO changes(vault_id, ts, device_id, path_id, version_id, kind, blob_ids, enc_meta)
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8) RETURNING seq"
                ),
                params![
                    vault,
                    ts,
                    req.device_id,
                    c.path_id,
                    c.version_id,
                    c.kind,
                    blob_ids,
                    c.enc_meta
                ],
                |r| r.get::<_, i64>(0),
            )
            .map_err(ApiErr::internal)?;
        let deleted = if c.kind == "delete" { 1 } else { 0 };
        tx.execute(
            "INSERT INTO heads(vault_id, path_id, head_version, deleted, seq)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(vault_id, path_id)
             DO UPDATE SET head_version=?3, deleted=?4, seq=?5",
            params![vault, c.path_id, c.version_id, deleted, last_seq],
        )
        .map_err(ApiErr::internal)?;
    }
    tx.commit().map_err(ApiErr::internal)?;

    // notify ws watchers
    let tx_opt = {
        let mut w = app.watchers.lock().map_err(|_| ApiErr::internal("lock"))?;
        match w.get(&vault) {
            Some(t) => Some(t.clone()),
            None => {
                let (tx, _rx) = broadcast::channel(64);
                w.insert(vault.clone(), tx.clone());
                Some(tx)
            }
        }
    };
    if let Some(t) = tx_opt {
        let _ = t.send(last_seq);
    }
    Ok(Json(json!({"ok": true, "seq": last_seq})))
}

/// WebSocket: replay changes after `seq`, then stream new ones.
async fn ws(
    State(app): State<Arc<App>>,
    Query(q): Query<WsQ>,
    headers: HeaderMap,
    wsup: WebSocketUpgrade,
) -> ApiResult<Response> {
    authed(&app, &headers, &q.vault)?;
    let vault = q.vault.clone();
    let mut seq = q.seq.unwrap_or(0);
    Ok(wsup.on_upgrade(move |mut socket| {
        let app = app.clone();
        async move {
            use axum::extract::ws::Message;
            // initial replay
            if let Ok(batch) = fetch_since(&app, &vault, seq) {
                for c in batch {
                    seq = c["seq"].as_i64().unwrap_or(seq);
                    let msg = json!({"type": "change", "change": c});
                    if socket
                        .send(Message::Text(msg.to_string().into()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            let rx = {
                let mut w = match app.watchers.lock() {
                    Ok(w) => w,
                    Err(_) => return,
                };
                w.entry(vault.clone())
                    .or_insert_with(|| broadcast::channel(64).0)
                    .subscribe()
            };
            let mut rx = rx;
            loop {
                match rx.recv().await {
                    Ok(new_seq) => {
                        if let Ok(batch) = fetch_since(&app, &vault, seq) {
                            for c in batch {
                                seq = c["seq"].as_i64().unwrap_or(seq);
                                let msg = json!({"type": "change", "change": c});
                                if socket
                                    .send(Message::Text(msg.to_string().into()))
                                    .await
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        let _ = new_seq;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => return,
                }
            }
        }
    }))
}

fn fetch_since(app: &App, vault: &str, since: i64) -> ApiResult<Vec<Value>> {
    let db = app.db.lock().map_err(|_| ApiErr::internal("db lock"))?;
    let mut st = db
        .prepare(&format!(
            "SELECT {CHANGE_COLS} FROM changes WHERE vault_id=?1 AND seq>?2 ORDER BY seq"
        ))
        .map_err(ApiErr::internal)?;
    let rows: Vec<Value> = st
        .query_map(params![vault, since], change_json)
        .map_err(ApiErr::internal)?
        .collect::<Result<_, _>>()
        .map_err(ApiErr::internal)?;
    Ok(rows)
}

/// fs helper kept small for the sim harness to reuse.
pub fn blob_file(data_dir: &FsPath, vault: &str, id: &str) -> PathBuf {
    data_dir.join("blobs").join(vault).join(id)
}
