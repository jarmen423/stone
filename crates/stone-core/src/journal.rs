//! Crash-safe sync journal (SQLite, WAL mode) in the cache dir.
//!
//! For every synced path the journal stores the last synced server version,
//! the plaintext hash, and a copy of the base text used as the 3-way merge
//! base. The journal is updated in the same transaction as each applied
//! change, so a crash mid-sync resumes cleanly.

use crate::error::Result;
use crate::paths;
use rusqlite::{params, Connection};
use std::path::Path;

/// One journaled path entry.
#[derive(Debug, Clone)]
pub struct JournalEntry {
    pub path: String,
    pub path_id: String,
    /// Server version id of the last synced state (None = never synced).
    pub version_id: Option<String>,
    /// Server sequence when this entry was synced.
    pub seq: i64,
    /// blake3 hex of the plaintext bytes synced.
    pub hash: String,
    /// Copy of the plaintext at `version_id` — the merge base.
    pub base: Vec<u8>,
    /// Whether the file is deleted (tombstone) on the server.
    pub deleted: bool,
}

/// Local change detected but not yet committed to the server.
#[derive(Debug, Clone)]
pub struct PendingChange {
    pub path: String,
    pub kind: PendingKind,
    /// For renames: the previous vault-relative path.
    pub old_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    Upsert,
    Delete,
    Rename,
}

pub struct Journal {
    conn: Connection,
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS paths(
                path TEXT PRIMARY KEY,
                path_id TEXT NOT NULL,
                version_id TEXT,
                seq INTEGER NOT NULL DEFAULT 0,
                hash TEXT NOT NULL,
                base BLOB NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_paths_pid ON paths(path_id);
            CREATE TABLE IF NOT EXISTS pending(
                path TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                old_path TEXT,
                queued_at INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    /// Open an in-memory journal (used by the simulation harness and tests).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
            CREATE TABLE IF NOT EXISTS paths(
                path TEXT PRIMARY KEY,
                path_id TEXT NOT NULL,
                version_id TEXT,
                seq INTEGER NOT NULL DEFAULT 0,
                hash TEXT NOT NULL,
                base BLOB NOT NULL,
                deleted INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_paths_pid ON paths(path_id);
            CREATE TABLE IF NOT EXISTS pending(
                path TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                old_path TEXT,
                queued_at INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { conn })
    }

    /// The last server sequence this device has fully applied.
    pub fn last_seq(&self) -> Result<i64> {
        self.meta_get_i64("last_seq")
    }

    pub fn set_last_seq(&self, seq: i64) -> Result<()> {
        self.meta_set("last_seq", &seq.to_string())
    }

    pub fn meta_get_i64(&self, k: &str) -> Result<i64> {
        let v: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k=?1", params![k], |r| r.get(0))
            .ok();
        Ok(v.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    pub fn meta_set(&self, k: &str, v: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta(k,v) VALUES(?1,?2) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn meta_get(&self, k: &str) -> Result<Option<String>> {
        let v: Option<String> = self
            .conn
            .query_row("SELECT v FROM meta WHERE k=?1", params![k], |r| r.get(0))
            .ok();
        Ok(v)
    }

    pub fn get(&self, path: &str) -> Result<Option<JournalEntry>> {
        let path = paths::normalize_rel(path);
        let row = self
            .conn
            .query_row(
                "SELECT path,path_id,version_id,seq,hash,base,deleted FROM paths WHERE path=?1",
                params![path],
                |r| {
                    Ok(JournalEntry {
                        path: r.get(0)?,
                        path_id: r.get(1)?,
                        version_id: r.get(2)?,
                        seq: r.get(3)?,
                        hash: r.get(4)?,
                        base: r.get(5)?,
                        deleted: r.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .ok();
        Ok(row)
    }

    /// Upsert a path entry. Call inside the same transaction as the disk write
    /// when applying remote changes (use `with_tx` + `upsert_tx`).
    pub fn upsert(&self, e: &JournalEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO paths(path,path_id,version_id,seq,hash,base,deleted)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(path) DO UPDATE SET
               path_id=excluded.path_id, version_id=excluded.version_id,
               seq=excluded.seq, hash=excluded.hash, base=excluded.base,
               deleted=excluded.deleted",
            params![e.path, e.path_id, e.version_id, e.seq, e.hash, e.base, e.deleted as i64],
        )?;
        Ok(())
    }

    pub fn remove(&self, path: &str) -> Result<()> {
        let path = paths::normalize_rel(path);
        self.conn
            .execute("DELETE FROM paths WHERE path=?1", params![path])?;
        Ok(())
    }

    /// Rename: keep the history chain — copy the entry under the new path.
    pub fn rename(&self, old: &str, new: &str) -> Result<()> {
        let old = paths::normalize_rel(old);
        let new = paths::normalize_rel(new);
        if let Some(mut e) = self.get(&old)? {
            e.path = new.clone();
            self.remove(&old)?;
            self.upsert(&e)?;
        }
        Ok(())
    }

    pub fn all_paths(&self) -> Result<Vec<JournalEntry>> {
        let mut st = self.conn.prepare(
            "SELECT path,path_id,version_id,seq,hash,base,deleted FROM paths ORDER BY path",
        )?;
        let rows = st.query_map([], |r| {
            Ok(JournalEntry {
                path: r.get(0)?,
                path_id: r.get(1)?,
                version_id: r.get(2)?,
                seq: r.get(3)?,
                hash: r.get(4)?,
                base: r.get(5)?,
                deleted: r.get::<_, i64>(6)? != 0,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // ---- pending (offline) queue ----

    pub fn queue_pending(&self, path: &str, kind: PendingKind, old_path: Option<&str>) -> Result<()> {
        let path = paths::normalize_rel(path);
        let kind_s = match kind {
            PendingKind::Upsert => "upsert",
            PendingKind::Delete => "delete",
            PendingKind::Rename => "rename",
        };
        let now = chrono::Utc::now().timestamp();
        self.conn.execute(
            "INSERT INTO pending(path,kind,old_path,queued_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(path) DO UPDATE SET kind=excluded.kind, old_path=excluded.old_path, queued_at=excluded.queued_at",
            params![path, kind_s, old_path, now],
        )?;
        Ok(())
    }

    pub fn clear_pending(&self, path: &str) -> Result<()> {
        let path = paths::normalize_rel(path);
        self.conn
            .execute("DELETE FROM pending WHERE path=?1", params![path])?;
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<PendingChange>> {
        let mut st = self
            .conn
            .prepare("SELECT path,kind,old_path FROM pending ORDER BY queued_at")?;
        let rows = st.query_map([], |r| {
            let kind_s: String = r.get(1)?;
            Ok(PendingChange {
                path: r.get(0)?,
                kind: match kind_s.as_str() {
                    "delete" => PendingKind::Delete,
                    "rename" => PendingKind::Rename,
                    _ => PendingKind::Upsert,
                },
                old_path: r.get(2)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Transaction wrapper — used when several journal rows must move with
    /// one filesystem change (crash safety requirement).
    pub fn transaction<R>(&mut self, f: impl FnOnce(&rusqlite::Transaction) -> Result<R>) -> Result<R> {
        let tx = self.conn.transaction()?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }
}
