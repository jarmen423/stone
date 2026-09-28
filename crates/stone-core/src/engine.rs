//! The vault engine: every vault operation funnels through here.
//! Writes are atomic (temp file + rename), recorded for sync in the journal's
//! pending queue, and reflected in the index immediately.

use crate::config::{self, VaultConfig, VaultLocal};
use crate::error::{Result, StoneError};
use crate::index::Index;
use crate::journal::{Journal, PendingKind};
use crate::links::{self, LinkEdit, VaultLinks};
use crate::parser;
use crate::paths;
use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// One logical vault open for operations.
pub struct Engine {
    pub root: PathBuf,
    pub cfg: VaultConfig,
    pub local: VaultLocal,
    journal: Journal,
}

/// A file changed by an engine operation (for one-commit batching + echo
/// suppression).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteRecord {
    pub path: String,
    pub hash: String,
    pub op: WriteOp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WriteOp {
    Create,
    Update,
    Delete,
    Rename,
}

impl Engine {
    /// Open a vault root (must contain `.stone/vault.toml`).
    pub fn open(root: &Path) -> Result<Self> {
        if !root.join(config::VAULT_TOML).is_file() {
            return Err(StoneError::VaultNotFound(root.display().to_string()));
        }
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        let cfg = config::load_vault_config(&root);
        let local_dir = config::vault_local_dir(&root);
        fs::create_dir_all(&local_dir)?;
        let local = VaultLocal { dir: local_dir };
        let journal = Journal::open(&local.journal_db())?;
        Ok(Self {
            root,
            cfg,
            local,
            journal,
        })
    }

    pub fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Open the index, then lazily refresh any stale entries (mtime/hash
    /// compare against disk). Keeps queries fresh without a daemon.
    pub fn index(&self) -> Result<Index> {
        let idx = Index::open(&self.local.index_db())?;
        self.refresh_index(&idx)?;
        Ok(idx)
    }

    /// Walk the vault and update index rows whose file hash changed.
    pub fn refresh_index(&self, idx: &Index) -> Result<usize> {
        let files = self.scan_files(false)?;
        let mut seen = std::collections::HashSet::new();
        let mut vl: Option<VaultLinks> = None;
        let mut changed = 0usize;
        for (rel, meta) in &files {
            if rel.starts_with(".stone/") {
                continue; // vault-internal settings — never indexed
            }
            seen.insert(rel.clone());
            let cur_hash = meta.hash.clone();
            if idx.indexed_hash(rel)? == Some(cur_hash) {
                continue;
            }
            if paths::is_text_like(rel) {
                let text = fs::read_to_string(paths::abs_from_rel(&self.root, rel))
                    .unwrap_or_default();
                if vl.is_none() {
                    vl = Some(self.vault_links_full(idx)?);
                }
                let vlr = vl.as_ref().unwrap();
                idx.update_note(rel, &text, meta.mtime, &|t| {
                    vlr.resolve(t).ok().flatten()
                })?;
                changed += 1;
            }
        }
        // drop index rows for files that vanished
        for p in idx.note_paths()? {
            if !seen.contains(&p) {
                idx.remove_note(&p)?;
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// VaultLinks built from index paths + aliases + all vault attachments.
    pub fn vault_links_full(&self, idx: &Index) -> Result<VaultLinks> {
        let mut vl = idx.vault_links()?;
        for (rel, meta) in self.scan_files(false)? {
            if !paths::is_markdown(&rel) {
                vl.add_file(&rel);
            } else if !vl.contains(&rel) {
                // brand-new file not yet indexed — parse headers minimally
                vl.add_file(&rel);
            }
            let _ = meta;
        }
        Ok(vl)
    }

    /// VaultLinks including aliases + block ids + headings by parsing every
    /// indexable file (slower; used by `mv` and ambiguity fixing).
    pub fn vault_links_parsed(&self) -> Result<VaultLinks> {
        let mut map: BTreeMap<String, parser::ParsedNote> = BTreeMap::new();
        for (rel, _meta) in self.scan_files(true)? {
            if paths::is_markdown(&rel) {
                let text = fs::read_to_string(paths::abs_from_rel(&self.root, &rel))
                    .unwrap_or_default();
                map.insert(rel.clone(), parser::parse(&text));
            }
        }
        let mut vl = VaultLinks::build(map.iter().map(|(p, n)| (p.as_str(), n)));
        for (rel, _) in self.scan_files(false)? {
            if !paths::is_markdown(&rel) {
                vl.add_file(&rel);
            }
        }
        Ok(vl)
    }

    // ---------------- file listing ----------------

    pub fn scan_files(&self, markdown_only: bool) -> Result<Vec<(String, FileMeta)>> {
        let excl = config::effective_excludes(&self.root);
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = fs::read_dir(&dir) else { continue };
            for ent in rd.flatten() {
                let path = ent.path();
                let Some(rel) = paths::rel_from_abs(&self.root, &path) else {
                    continue;
                };
                if excl.is_excluded(&rel) {
                    continue;
                }
                let ft = ent.file_type().map_err(StoneError::Io)?;
                if ft.is_dir() {
                    // don't descend into excluded dirs
                    if rel == ".git" || rel == ".trash" || rel == ".obsidian" {
                        // .obsidian is read-only for us but not synced;
                        // still index? No — spec: cache dir, .git, .trash, junk
                        // excluded; .obsidian we read but never write/sync.
                        if rel == ".obsidian" {
                            continue;
                        }
                        continue;
                    }
                    stack.push(path);
                } else if ft.is_file() {
                    if rel.starts_with(".stone/") && rel != ".stone/vault.toml" && rel != ".stone/sync.toml" {
                        // .stone contents are synced EXCEPT trash (excluded above)
                    }
                    if markdown_only && !paths::is_markdown(&rel) {
                        continue;
                    }
                    let md = ent.metadata().map_err(StoneError::Io)?;
                    let mtime = md
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let hash = if paths::is_text_like(&rel) {
                        fs::read(&path)
                            .map(|b| blake3::hash(&b).to_hex().to_string())
                            .unwrap_or_default()
                    } else {
                        String::new()
                    };
                    out.push((
                        rel,
                        FileMeta {
                            mtime,
                            size: md.len(),
                            hash,
                        },
                    ));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    // ---------------- note resolution ----------------

    /// Resolve a note name/path to a vault-relative path.
    /// Accepts literal paths (`a/b.md`), bare names (`Note`), and aliases.
    pub fn resolve_note(&self, name: &str) -> Result<String> {
        let n = paths::normalize_rel(name);
        let idx = self.index()?;
        // exact path?
        if n.contains('/') || n.to_lowercase().ends_with(".md") {
            let with_md = paths::with_md(&n);
            for cand in [&n, &with_md] {
                let abs = paths::abs_from_rel(&self.root, cand);
                if abs.is_file() {
                    return Ok(cand.clone());
                }
            }
        }
        let vl = self.vault_links_full(&idx)?;
        match vl.resolve(&n) {
            Ok(Some(p)) => Ok(p),
            Ok(None) => Err(StoneError::NotFound(name.to_string())),
            Err(e) => Err(e),
        }
    }

    // ---------------- reads ----------------

    pub fn cat(&self, note: &str) -> Result<String> {
        let path = self.resolve_note(note)?;
        let abs = paths::abs_from_rel(&self.root, &path);
        fs::read_to_string(&abs).map_err(|_| StoneError::NotFound(note.to_string()))
    }

    // ---------------- writes ----------------

    /// Atomic write of a vault-relative file: temp file then rename, record
    /// for echo suppression + journal pending.
    pub fn write_file(&self, rel: &str, bytes: &[u8]) -> Result<WriteRecord> {
        let rel = paths::normalize_rel(rel);
        paths::validate_rel(&rel)?;
        let abs = paths::abs_from_rel(&self.root, &rel);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = abs.with_extension("tmp-stone");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &abs)?;
        let hash = blake3::hash(bytes).to_hex().to_string();
        self.journal.queue_pending(&rel, PendingKind::Upsert, None)?;
        Ok(WriteRecord {
            path: rel,
            hash,
            op: WriteOp::Update,
        })
    }

    /// Delete to trash (`.stone/trash/` inside the vault — restorable).
    pub fn trash_file(&self, rel: &str) -> Result<String> {
        let rel = paths::normalize_rel(rel);
        let abs = paths::abs_from_rel(&self.root, &rel);
        if !abs.is_file() {
            return Err(StoneError::NotFound(rel));
        }
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let name = links::basename(&rel).replace(' ', "_");
        let mut dest_rel = format!("{}/{}-{}", config::TRASH_DIR, ts, name);
        let mut i = 1;
        while paths::abs_from_rel(&self.root, &dest_rel).exists() {
            dest_rel = format!("{}/{}-{}-{}", config::TRASH_DIR, ts, i, name);
            i += 1;
        }
        let dest = paths::abs_from_rel(&self.root, &dest_rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&abs, &dest)?;
        self.journal.queue_pending(&rel, PendingKind::Delete, None)?;
        Ok(dest_rel)
    }

    /// Rename/move on disk. Returns the record; backlinks rewrite is separate
    /// (`mv`) so callers can control batching.
    pub fn rename_file(&self, old: &str, new: &str) -> Result<WriteRecord> {
        let old = paths::normalize_rel(old);
        let new = paths::normalize_rel(new);
        paths::validate_rel(&new)?;
        let abs_old = paths::abs_from_rel(&self.root, &old);
        let abs_new = paths::abs_from_rel(&self.root, &new);
        if !abs_old.exists() {
            return Err(StoneError::NotFound(old));
        }
        if abs_new.exists() {
            return Err(StoneError::Conflict(format!("{new} already exists")));
        }
        if let Some(parent) = abs_new.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&abs_old, &abs_new)?;
        self.journal
            .queue_pending(&new, PendingKind::Rename, Some(&old))?;
        self.journal.rename(&old, &new)?;
        let hash = fs::read(&abs_new)
            .map(|b| blake3::hash(&b).to_hex().to_string())
            .unwrap_or_default();
        Ok(WriteRecord {
            path: new,
            hash,
            op: WriteOp::Rename,
        })
    }

    /// `stone mv`: rename + rewrite every resolvable backlink in one batch.
    /// Returns (new_path, rewrite diffs). All file changes share one sync
    /// commit because they're all queued in `pending` before `sync now`.
    pub fn mv(&self, old: &str, new: &str, dry_run: bool) -> Result<MvResult> {
        let old_path = self.resolve_note(old)?;
        let new_path = paths::with_md(&paths::normalize_rel(new));

        // gather docs containing candidate links (only markdown files; cheap
        // filter: docs whose text mentions the old basename)
        let vl = self.vault_links_parsed()?;
        let mut docs: BTreeMap<String, String> = BTreeMap::new();
        let old_stem = links::strip_ext(links::basename(&old_path)).to_string();
        for (rel, _meta) in self.scan_files(true)? {
            if rel == old_path {
                continue;
            }
            let text = fs::read_to_string(paths::abs_from_rel(&self.root, &rel))
                .unwrap_or_default();
            if text.contains("[[") {
                docs.insert(rel, text);
            }
        }
        let mut plan = links::plan_rename_rewrites(&vl, &docs, &old_path, &new_path)?;

        // detect newly-ambiguous links created by the rename (basename clash)
        let mut ambiguity_fixes: BTreeMap<String, Vec<LinkEdit>> = BTreeMap::new();
        {
            let mut post = vl.clone();
            if let Some(meta) = post.notes.remove(&old_path) {
                let mut m = meta;
                m.path = new_path.clone();
                post.notes.insert(new_path.clone(), m);
            }
            for (path, link, _cands) in links::find_ambiguous_links(&post, &docs) {
                if plan.get(&path).map(|v| v.iter().any(|e| e.span_start == link.target_span.start)).unwrap_or(false) {
                    continue; // already rewritten
                }
                let fixed = post.minimal_target_ambiguous(&link.target);
                if let Some(fixed) = fixed {
                    ambiguity_fixes.entry(path.clone()).or_default().push(LinkEdit {
                        path: path.clone(),
                        span_start: link.target_span.start,
                        span_end: link.target_span.end,
                        old_text: link.target.clone(),
                        new_text: fixed,
                    });
                }
            }
        }
        for (p, mut edits) in ambiguity_fixes {
            edits.sort_by_key(|e| std::cmp::Reverse(e.span_start));
            plan.entry(p).or_default().extend(edits);
            let _ = old_stem;
        }

        let mut diffs = Vec::new();
        for (p, edits) in &plan {
            for e in edits {
                diffs.push(MvDiff {
                    file: p.clone(),
                    line: line_of(&docs[p], e.span_start),
                    old: e.old_text.clone(),
                    new: e.new_text.clone(),
                });
            }
        }

        if !dry_run {
            // apply link edits (descending span start), then rename
            for (p, edits) in &plan {
                let text = &docs[p];
                let new_text = links::apply_edits(text, edits);
                self.write_file(p, new_text.as_bytes())?;
            }
            self.rename_file(&old_path, &new_path)?;
            // update index rows for touched files
            if let Ok(idx) = Index::open(&self.local.index_db()) {
                for (p, _) in &plan {
                    if let Ok(text) =
                        fs::read_to_string(paths::abs_from_rel(&self.root, p))
                    {
                        let _ = self.refresh_one(&idx, p, &text);
                    }
                }
                if let Ok(text) = fs::read_to_string(paths::abs_from_rel(&self.root, &new_path)) {
                    let _ = idx.rename_note(&old_path, &new_path, &text, now_mtime());
                }
            }
        }

        Ok(MvResult {
            from: old_path,
            to: new_path,
            edits: diffs,
            files_touched: plan.len(),
        })
    }

    fn refresh_one(&self, idx: &Index, rel: &str, text: &str) -> Result<()> {
        let vl = self.vault_links_full(idx)?;
        idx.update_note(rel, text, now_mtime(), &|t| vl.resolve(t).ok().flatten())
    }

    /// Create a note. `template` names a note under the templates folder.
    pub fn new_note(
        &self,
        name: &str,
        content: Option<&str>,
        template: Option<&str>,
    ) -> Result<String> {
        let rel = if name.contains('/') || name.to_lowercase().ends_with(".md") {
            paths::with_md(name)
        } else {
            let folder = self
                .cfg
                .new_notes_folder
                .clone()
                .or_else(|| config::obsidian_defaults(&self.root).new_notes_folder)
                .unwrap_or_default();
            let base = if folder.is_empty() {
                name.to_string()
            } else {
                format!("{folder}/{name}")
            };
            paths::with_md(&base)
        };
        let abs = paths::abs_from_rel(&self.root, &rel);
        if abs.exists() {
            return Err(StoneError::Conflict(format!("{rel} already exists")));
        }
        let body = match (content, template) {
            (Some(c), _) => c.to_string(),
            (None, Some(t)) => self.load_template(t)?,
            (None, None) => String::new(),
        };
        self.write_file(&rel, body.as_bytes())?;
        Ok(rel)
    }

    fn load_template(&self, name: &str) -> Result<String> {
        let folder = self
            .cfg
            .templates_folder
            .clone()
            .or_else(|| config::obsidian_defaults(&self.root).templates_folder)
            .unwrap_or_default();
        let rel = paths::with_md(&format!("{folder}/{name}"));
        let abs = paths::abs_from_rel(&self.root, &rel);
        let text = fs::read_to_string(&abs)
            .map_err(|_| StoneError::NotFound(format!("template {name}")))?;
        Ok(crate::templating::render(&text))
    }

    /// Append/prepend text to a note (creates it if missing for append).
    pub fn append(&self, note: &str, text: &str) -> Result<String> {
        let path = self.resolve_note_or_create(note)?;
        let cur = fs::read_to_string(paths::abs_from_rel(&self.root, &path)).unwrap_or_default();
        let sep = if cur.is_empty() || cur.ends_with('\n') { "" } else { "\n" };
        self.write_file(&path, format!("{cur}{sep}{text}").as_bytes())?;
        Ok(path)
    }

    pub fn prepend(&self, note: &str, text: &str) -> Result<String> {
        let path = self.resolve_note_or_create(note)?;
        let cur = fs::read_to_string(paths::abs_from_rel(&self.root, &path)).unwrap_or_default();
        let new = format!("{text}\n{cur}");
        self.write_file(&path, new.as_bytes())?;
        Ok(path)
    }

    /// `stone edit <note> --find X --replace Y [--all]`
    pub fn edit(&self, note: &str, find: &str, replace: &str, all: bool) -> Result<EditResult> {
        let path = self.resolve_note(note)?;
        let cur = fs::read_to_string(paths::abs_from_rel(&self.root, &path))
            .map_err(|_| StoneError::NotFound(note.into()))?;
        if !cur.contains(find) {
            return Err(StoneError::NotFound(format!("text not found in {note}")));
        }
        let (new, count) = if all {
            (cur.replace(find, replace), cur.matches(find).count())
        } else {
            (cur.replacen(find, replace, 1), 1)
        };
        self.write_file(&path, new.as_bytes())?;
        Ok(EditResult { path, count })
    }

    /// Daily note: create if missing, optionally append.
    pub fn daily(&self, date: Option<&str>, append: Option<&str>) -> Result<String> {
        let date = match date {
            Some("yesterday") => {
                (chrono::Utc::now() - chrono::Duration::days(1)).date_naive()
            }
            Some("today") | None => chrono::Utc::now().date_naive(),
            Some(d) => chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d")
                .map_err(|_| StoneError::InvalidInput(format!("bad date {d}")))?,
        };
        let (folder, format) = config::daily_settings(&self.root, &self.cfg);
        let name = date.format(&format).to_string();
        let rel = if folder.is_empty() {
            paths::with_md(&name)
        } else {
            paths::with_md(&format!("{folder}/{name}"))
        };
        let abs = paths::abs_from_rel(&self.root, &rel);
        if !abs.exists() {
            self.write_file(&rel, b"")?;
        }
        if let Some(text) = append {
            let cur = fs::read_to_string(&abs).unwrap_or_default();
            let sep = if cur.is_empty() || cur.ends_with('\n') { "" } else { "\n" };
            self.write_file(&rel, format!("{cur}{sep}{text}\n").as_bytes())?;
        }
        Ok(rel)
    }

    /// Set a frontmatter property (surgical: only the fm block is rewritten).
    pub fn prop_set(&self, note: &str, key: &str, value: &str) -> Result<String> {
        let path = self.resolve_note(note)?;
        let text = fs::read_to_string(paths::abs_from_rel(&self.root, &path))
            .map_err(|_| StoneError::NotFound(note.into()))?;
        let new_text = crate::frontmatter::set_prop(&text, key, value)?;
        self.write_file(&path, new_text.as_bytes())?;
        Ok(path)
    }

    fn resolve_note_or_create(&self, note: &str) -> Result<String> {
        match self.resolve_note(note) {
            Ok(p) => Ok(p),
            Err(StoneError::NotFound(_)) => Ok(paths::with_md(&paths::normalize_rel(note))),
            Err(e) => Err(e),
        }
    }

    /// List trash entries.
    pub fn trash_list(&self) -> Result<Vec<String>> {
        let trash = self.root.join(config::TRASH_DIR);
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(&trash) {
            for e in rd.flatten() {
                out.push(e.file_name().to_string_lossy().to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Restore a trashed file to `dest_rel`.
    pub fn trash_restore(&self, name: &str, dest_rel: &str) -> Result<String> {
        let src = self.root.join(config::TRASH_DIR).join(name);
        if !src.is_file() {
            return Err(StoneError::NotFound(name.into()));
        }
        let dest_rel = paths::with_md(dest_rel);
        let dest = paths::abs_from_rel(&self.root, &dest_rel);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::rename(&src, &dest)?;
        self.journal.queue_pending(&dest_rel, PendingKind::Upsert, None)?;
        Ok(dest_rel)
    }
}

#[derive(Debug, Clone)]
pub struct FileMeta {
    pub mtime: i64,
    pub size: u64,
    pub hash: String,
}

#[derive(Debug, Serialize)]
pub struct MvResult {
    pub from: String,
    pub to: String,
    pub edits: Vec<MvDiff>,
    pub files_touched: usize,
}

#[derive(Debug, Serialize)]
pub struct MvDiff {
    pub file: String,
    pub line: usize,
    pub old: String,
    pub new: String,
}

#[derive(Debug, Serialize)]
pub struct EditResult {
    pub path: String,
    pub count: usize,
}

fn now_mtime() -> i64 {
    chrono::Utc::now().timestamp()
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())].matches('\n').count() + 1
}
