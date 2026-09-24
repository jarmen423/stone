//! Vault index: SQLite (WAL) + FTS5 in the cache dir.
//! Rebuildable entirely from vault files; updated incrementally on writes
//! and by the file watcher. Query surface: search, backlinks, links,
//! unresolved, orphans, tags, properties, tasks, graph.

use crate::error::Result;
use crate::links::{self, VaultLinks};
use crate::parser::{self, ParsedNote};
use crate::paths;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS notes(
    path TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    mtime INTEGER NOT NULL DEFAULT 0,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    frontmatter TEXT,
    aliases TEXT
);
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(
    path UNINDEXED, title, body, tags, properties
);
CREATE TABLE IF NOT EXISTS links(
    src TEXT NOT NULL, dst_raw TEXT NOT NULL, dst_resolved TEXT,
    span_start INTEGER NOT NULL, span_end INTEGER NOT NULL,
    embed INTEGER NOT NULL DEFAULT 0, line INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_links_dst ON links(dst_resolved);
CREATE INDEX IF NOT EXISTS idx_links_src ON links(src);
CREATE TABLE IF NOT EXISTS tags(path TEXT NOT NULL, tag TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_tags_tag ON tags(tag);
CREATE TABLE IF NOT EXISTS tasks(
    path TEXT NOT NULL, line INTEGER NOT NULL, done INTEGER NOT NULL, text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS props(path TEXT NOT NULL, key TEXT NOT NULL, value TEXT);
CREATE INDEX IF NOT EXISTS idx_props_key ON props(key);
CREATE TABLE IF NOT EXISTS index_state(path TEXT PRIMARY KEY, hash TEXT NOT NULL);
";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub path: String,
    pub title: String,
    pub snippet: String,
    pub rank: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkRow {
    pub src: String,
    pub dst_raw: String,
    pub dst_resolved: Option<String>,
    pub line: usize,
    pub embed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRow {
    pub path: String,
    pub line: usize,
    pub done: bool,
    pub text: String,
}

/// Parsed `stone search` query: `tag:#x path:dir "phrase" terms`.
#[derive(Debug, Clone, Default)]
pub struct SearchQuery {
    pub tags: Vec<String>,
    pub path_prefixes: Vec<String>,
    pub terms: Vec<String>,
    /// Content-equals filters on properties: `prop:key=value`.
    pub props: Vec<(String, String)>,
}

pub fn parse_search_query(q: &str) -> SearchQuery {
    let mut out = SearchQuery::default();
    let mut rest = q;
    // extract quoted phrases first
    let mut phrases = Vec::new();
    let mut rebuilt = String::new();
    while let Some(start) = rest.find('"') {
        rebuilt.push_str(&rest[..start]);
        if let Some(end) = rest[start + 1..].find('"') {
            phrases.push(rest[start + 1..start + 1 + end].to_string());
            rest = &rest[start + 1 + end + 1..];
        } else {
            rebuilt.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    rebuilt.push_str(rest);
    for tok in rebuilt.split_whitespace() {
        if let Some(tag) = tok.strip_prefix("tag:") {
            out.tags.push(tag.trim_start_matches('#').to_string());
        } else if let Some(p) = tok.strip_prefix("path:") {
            out.path_prefixes.push(paths::normalize_rel(p));
        } else if let Some(pv) = tok.strip_prefix("prop:") {
            if let Some((k, v)) = pv.split_once('=') {
                out.props.push((k.to_string(), v.to_string()));
            }
        } else {
            out.terms.push(tok.to_string());
        }
    }
    for ph in phrases {
        if !ph.is_empty() {
            out.terms.push(format!("\"{ph}\""));
        }
    }
    out
}

fn fts_escape(s: &str) -> String {
    s.replace('"', "\"\"")
}

pub struct Index {
    pub conn: Connection,
}

impl Index {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    /// Insert/replace a note's indexed data. `resolved` maps raw link targets
    /// to vault paths (from `VaultLinks::resolve`).
    pub fn update_note(
        &self,
        path: &str,
        text: &str,
        mtime: i64,
        resolved: &dyn Fn(&str) -> Option<String>,
    ) -> Result<()> {
        let path = paths::normalize_rel(path);
        let parsed = parser::parse(text);
        self.update_parsed(&path, &parsed, text, mtime, resolved)
    }

    pub fn update_parsed(
        &self,
        path: &str,
        parsed: &ParsedNote,
        text: &str,
        mtime: i64,
        resolved: &dyn Fn(&str) -> Option<String>,
    ) -> Result<()> {
        let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
        let title = parsed
            .title()
            .unwrap_or_else(|| links::strip_ext(links::basename(path)).to_string());
        let fm_json = parsed
            .frontmatter
            .as_ref()
            .and_then(|f| f.value.clone())
            .and_then(|v| serde_yaml::to_string(&v).ok());
        let aliases = serde_json::to_string(&parsed.aliases())?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM links WHERE src=?1", params![path])?;
        tx.execute("DELETE FROM tags WHERE path=?1", params![path])?;
        tx.execute("DELETE FROM tasks WHERE path=?1", params![path])?;
        tx.execute("DELETE FROM props WHERE path=?1", params![path])?;
        tx.execute("DELETE FROM notes_fts WHERE path=?1", params![path])?;
        tx.execute(
            "INSERT INTO notes(path,title,mtime,hash,size,frontmatter,aliases)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(path) DO UPDATE SET title=excluded.title, mtime=excluded.mtime,
               hash=excluded.hash, size=excluded.size, frontmatter=excluded.frontmatter,
               aliases=excluded.aliases",
            params![path, title, mtime, hash, text.len() as i64, fm_json, aliases],
        )?;
        // tags column: space-joined for FTS matching
        let tag_str = parsed
            .tags
            .iter()
            .map(|t| format!("#{}", t.name))
            .collect::<Vec<_>>()
            .join(" ");
        let prop_str = prop_strings(parsed).join(" ");
        tx.execute(
            "INSERT INTO notes_fts(path,title,body,tags,properties) VALUES(?1,?2,?3,?4,?5)",
            params![path, title, text, tag_str, prop_str],
        )?;
        for link in &parsed.links {
            let dst = resolved(&link.target);
            tx.execute(
                "INSERT INTO links(src,dst_raw,dst_resolved,span_start,span_end,embed,line)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    path,
                    link.inner,
                    dst,
                    link.span.start as i64,
                    link.span.end as i64,
                    link.embed as i64,
                    line_of(text, link.span.start) as i64
                ],
            )?;
        }
        for tag in &parsed.tags {
            tx.execute("INSERT INTO tags(path,tag) VALUES(?1,?2)", params![path, tag.name])?;
        }
        for task in &parsed.tasks {
            tx.execute(
                "INSERT INTO tasks(path,line,done,text) VALUES(?1,?2,?3,?4)",
                params![path, task.line as i64, task.done as i64, task.text],
            )?;
        }
        if let Some(fm) = &parsed.frontmatter {
            if let Some(YamlValue::Mapping(map)) = &fm.value {
                for (k, v) in map {
                    if let Some(key) = yaml_scalar(k) {
                        let val = yaml_scalar(v).unwrap_or_else(|| yaml_brief(v));
                        tx.execute(
                            "INSERT INTO props(path,key,value) VALUES(?1,?2,?3)",
                            params![path, key, val],
                        )?;
                    }
                }
            }
        }
        tx.execute(
            "INSERT INTO index_state(path,hash) VALUES(?1,?2)
             ON CONFLICT(path) DO UPDATE SET hash=excluded.hash",
            params![path, hash],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn remove_note(&self, path: &str) -> Result<()> {
        let path = paths::normalize_rel(path);
        let tx = self.conn.unchecked_transaction()?;
        for t in ["links", "tags", "tasks", "props", "notes_fts", "index_state"] {
            let col = if t == "links" { "src" } else { "path" };
            tx.execute(
                &format!("DELETE FROM {t} WHERE {col}=?1"),
                params![path],
            )?;
        }
        tx.execute("DELETE FROM notes WHERE path=?1", params![path])?;
        tx.commit()?;
        Ok(())
    }

    pub fn rename_note(&self, old: &str, new: &str, text: &str, mtime: i64) -> Result<()> {
        self.remove_note(old)?;
        let vl = self.vault_links()?;
        self.update_note(new, text, mtime, &|t| vl.resolve(t).ok().flatten())
    }

    /// Hash recorded in the index for `path` — used for lazy freshness checks.
    pub fn indexed_hash(&self, path: &str) -> Result<Option<String>> {
        let path = paths::normalize_rel(path);
        Ok(self
            .conn
            .query_row(
                "SELECT hash FROM index_state WHERE path=?1",
                params![path],
                |r| r.get(0),
            )
            .ok())
    }

    pub fn note_paths(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare("SELECT path FROM notes ORDER BY path")?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Rebuild the VaultLinks namespace from the index (paths + aliases).
    pub fn vault_links(&self) -> Result<VaultLinks> {
        let mut st = self
            .conn
            .prepare("SELECT path, aliases, frontmatter FROM notes")?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        let mut vl = VaultLinks { notes: BTreeMap::new() };
        for r in rows {
            let (path, aliases_json, _fm) = r?;
            let aliases: Vec<String> = aliases_json
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default();
            vl.notes.insert(
                path.clone(),
                links::NoteMeta {
                    path,
                    aliases,
                    block_ids: BTreeSet::new(),
                    headings: BTreeSet::new(),
                },
            );
        }
        Ok(vl)
    }

    /// Register attachments so `![[img.png]]` resolves.
    pub fn register_attachment(&self, path: &str) -> Result<()> {
        let path = paths::normalize_rel(path);
        self.conn.execute(
            "INSERT INTO notes(path,title,mtime,hash,size) VALUES(?1,?2,0,'',0)
             ON CONFLICT(path) DO NOTHING",
            params![path, links::basename(&path)],
        )?;
        Ok(())
    }

    // ---------- queries ----------

    /// `stone search` — FTS + tag/path/prop filters.
    pub fn search(&self, q: &SearchQuery, limit: usize) -> Result<Vec<SearchHit>> {
        let mut where_clauses = Vec::new();
        let mut args: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        if !q.terms.is_empty() {
            let match_expr = q
                .terms
                .iter()
                .map(|t| {
                    if t.starts_with('"') && t.ends_with('"') {
                        format!("\"{}\"", fts_escape(&t[1..t.len() - 1]))
                    } else {
                        format!("\"{}\"", fts_escape(t))
                    }
                })
                .collect::<Vec<_>>()
                .join(" AND ");
            where_clauses.push(format!("notes_fts MATCH ?{}", args.len() + 1));
            args.push(Box::new(match_expr));
        }
        for (i, tag) in q.tags.iter().enumerate() {
            where_clauses.push(format!(
                "EXISTS (SELECT 1 FROM tags t WHERE t.path = notes_fts.path AND (t.tag = ?{} OR t.tag LIKE ?{} || '/%'))",
                args.len() + 1,
                args.len() + 2
            ));
            let _ = i;
            args.push(Box::new(tag.clone()));
            args.push(Box::new(tag.clone()));
        }
        for p in &q.path_prefixes {
            where_clauses.push(format!(
                "(notes_fts.path = ?{} OR notes_fts.path LIKE ?{} || '/%')",
                args.len() + 1,
                args.len() + 2
            ));
            args.push(Box::new(p.clone()));
            args.push(Box::new(p.clone()));
        }
        for (k, v) in &q.props {
            where_clauses.push(format!(
                "EXISTS (SELECT 1 FROM props pr WHERE pr.path = notes_fts.path AND pr.key = ?{} AND pr.value = ?{})",
                args.len() + 1,
                args.len() + 2
            ));
            args.push(Box::new(k.clone()));
            args.push(Box::new(v.clone()));
        }
        args.push(Box::new(limit as i64));
        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT notes_fts.path, n.title, snippet(notes_fts, 2, '[', ']', '…', 12), rank
             FROM notes_fts JOIN notes n ON n.path = notes_fts.path
             {where_sql} ORDER BY rank LIMIT ?{}",
            args.len()
        );
        let mut st = self.conn.prepare(&sql)?;
        let arg_refs: Vec<&dyn rusqlite::types::ToSql> =
            args.iter().map(|a| a.as_ref()).collect();
        let rows = st.query_map(arg_refs.as_slice(), |r| {
            Ok(SearchHit {
                path: r.get(0)?,
                title: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                snippet: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                rank: r.get::<_, f64>(3).unwrap_or(0.0),
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Notes linking TO `path` (backlinks).
    pub fn backlinks(&self, path: &str) -> Result<Vec<LinkRow>> {
        let path = paths::normalize_rel(path);
        let mut st = self.conn.prepare(
            "SELECT src,dst_raw,dst_resolved,line,embed FROM links WHERE dst_resolved=?1 ORDER BY src",
        )?;
        let rows = st.query_map(params![path], row_to_link)?;
        collect_rows(rows)
    }

    /// Outgoing links FROM `path`.
    pub fn links_from(&self, path: &str) -> Result<Vec<LinkRow>> {
        let path = paths::normalize_rel(path);
        let mut st = self.conn.prepare(
            "SELECT src,dst_raw,dst_resolved,line,embed FROM links WHERE src=?1 ORDER BY span_start",
        )?;
        let rows = st.query_map(params![path], row_to_link)?;
        collect_rows(rows)
    }

    /// Links that resolve to nothing.
    pub fn unresolved(&self, path: Option<&str>) -> Result<Vec<LinkRow>> {
        let (sql, args): (String, Vec<String>) = match path {
            Some(p) => (
                "SELECT src,dst_raw,dst_resolved,line,embed FROM links WHERE dst_resolved IS NULL AND src=?1".into(),
                vec![paths::normalize_rel(p)],
            ),
            None => (
                "SELECT src,dst_raw,dst_resolved,line,embed FROM links WHERE dst_resolved IS NULL".into(),
                vec![],
            ),
        };
        let mut st = self.conn.prepare(&sql)?;
        let arg_refs: Vec<&dyn rusqlite::types::ToSql> =
            args.iter().map(|s| s as &dyn rusqlite::types::ToSql).collect();
        let rows = st.query_map(arg_refs.as_slice(), row_to_link)?;
        collect_rows(rows)
    }

    /// Notes with no incoming links.
    pub fn orphans(&self) -> Result<Vec<String>> {
        let mut st = self.conn.prepare(
            "SELECT path FROM notes n WHERE NOT EXISTS (
                SELECT 1 FROM links l WHERE l.dst_resolved = n.path AND l.src != n.path
             ) AND n.hash != '' ORDER BY path",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// All tags with counts.
    pub fn all_tags(&self) -> Result<Vec<(String, i64)>> {
        let mut st = self
            .conn
            .prepare("SELECT tag, COUNT(DISTINCT path) FROM tags GROUP BY tag ORDER BY tag")?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Tasks, optionally only open ones.
    pub fn tasks(&self, open_only: bool) -> Result<Vec<TaskRow>> {
        let sql = if open_only {
            "SELECT path,line,done,text FROM tasks WHERE done=0 ORDER BY path,line"
        } else {
            "SELECT path,line,done,text FROM tasks ORDER BY path,line"
        };
        let mut st = self.conn.prepare(sql)?;
        let rows = st.query_map([], |r| {
            Ok(TaskRow {
                path: r.get(0)?,
                line: r.get::<_, i64>(1)? as usize,
                done: r.get::<_, i64>(2)? != 0,
                text: r.get(3)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Property query: `key` alone (exists) or `key=value`.
    pub fn props_query(&self, key: &str, value: Option<&str>) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        match value {
            Some(v) => {
                let mut st = self
                    .conn
                    .prepare("SELECT path, value FROM props WHERE key=?1 AND value=?2 ORDER BY path")?;
                let rows = st.query_map(params![key, v], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))
                })?;
                for r in rows {
                    out.push(r?);
                }
            }
            None => {
                let mut st = self
                    .conn
                    .prepare("SELECT path, value FROM props WHERE key=?1 ORDER BY path")?;
                let rows = st.query_map(params![key], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?.unwrap_or_default()))
                })?;
                for r in rows {
                    out.push(r?);
                }
            }
        }
        Ok(out)
    }

    pub fn prop_get(&self, path: &str, key: &str) -> Result<Option<String>> {
        let path = paths::normalize_rel(path);
        Ok(self
            .conn
            .query_row(
                "SELECT value FROM props WHERE path=?1 AND key=?2",
                params![path, key],
                |r| r.get(0),
            )
            .ok())
    }

    /// All note→note resolved edges for `stone graph`.
    pub fn edges(&self) -> Result<Vec<(String, String)>> {
        let mut st = self.conn.prepare(
            "SELECT DISTINCT src, dst_resolved FROM links WHERE dst_resolved IS NOT NULL AND embed=0",
        )?;
        let rows = st.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Get a note's current text-adjacent metadata (title).
    pub fn note_title(&self, path: &str) -> Result<Option<String>> {
        let path = paths::normalize_rel(path);
        Ok(self
            .conn
            .query_row(
                "SELECT title FROM notes WHERE path=?1",
                params![path],
                |r| r.get(0),
            )
            .ok())
    }
}

fn row_to_link(r: &rusqlite::Row) -> rusqlite::Result<LinkRow> {
    Ok(LinkRow {
        src: r.get(0)?,
        dst_raw: r.get(1)?,
        dst_resolved: r.get(2)?,
        line: r.get::<_, i64>(3)? as usize,
        embed: r.get::<_, i64>(4)? != 0,
    })
}

fn collect_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row) -> rusqlite::Result<LinkRow>>,
) -> Result<Vec<LinkRow>> {
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count()
}

fn yaml_scalar(v: &YamlValue) -> Option<String> {
    match v {
        YamlValue::String(s) => Some(s.clone()),
        YamlValue::Number(n) => Some(n.to_string()),
        YamlValue::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn yaml_brief(v: &YamlValue) -> String {
    serde_yaml::to_string(v)
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn prop_strings(parsed: &ParsedNote) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(fm) = &parsed.frontmatter {
        if let Some(YamlValue::Mapping(map)) = &fm.value {
            for (k, v) in map {
                if let Some(key) = yaml_scalar(k) {
                    out.push(format!("{key}: {}", yaml_brief(v)));
                }
            }
        }
    }
    out
}
