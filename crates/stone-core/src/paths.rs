//! Vault-relative path handling: Unicode NFC normalization, validation,
//! case-collision detection, and sync exclusion rules.

use crate::error::{Result, StoneError};
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::{Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

/// Normalize a vault-relative path: NFC, forward slashes, no leading `./`.
pub fn normalize_rel(rel: &str) -> String {
    let cleaned = rel.replace('\\', "/");
    let mut out = cleaned.trim_start_matches("./").to_string();
    while out.ends_with('/') && out.len() > 1 {
        out.pop();
    }
    out.nfc().collect()
}

/// Validate a vault-relative path: no absolute paths, no `..`, non-empty.
pub fn validate_rel(rel: &str) -> Result<()> {
    if rel.is_empty() {
        return Err(StoneError::InvalidInput("empty path".into()));
    }
    if rel.starts_with('/') || rel.starts_with('\\') {
        return Err(StoneError::InvalidInput(format!(
            "absolute path not allowed: {rel}"
        )));
    }
    for part in rel.replace('\\', "/").split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(StoneError::InvalidInput(format!(
                "bad path component `{part}` in {rel}"
            )));
        }
    }
    Ok(())
}

/// Convert an absolute path inside the vault to a normalized relative path.
pub fn rel_from_abs(vault_root: &Path, abs: &Path) -> Option<String> {
    let rel = abs.strip_prefix(vault_root).ok()?;
    let s = rel.to_string_lossy().replace('\\', "/");
    Some(normalize_rel(&s))
}

/// Vault-relative path → absolute path under the vault root (no `..`).
pub fn abs_from_rel(vault_root: &Path, rel: &str) -> PathBuf {
    let mut p = vault_root.to_path_buf();
    for part in rel.split('/') {
        if !part.is_empty() && part != "." && part != ".." {
            p.push(part);
        }
    }
    p
}

/// True for paths that are note-like or file-like user content (not dot-dirs handled by excludes).
pub fn is_markdown(rel: &str) -> bool {
    rel.to_lowercase().ends_with(".md")
}

pub fn is_canvas(rel: &str) -> bool {
    rel.to_lowercase().ends_with(".canvas")
}

pub fn is_text_like(rel: &str) -> bool {
    let lower = rel.to_lowercase();
    lower.ends_with(".md")
        || lower.ends_with(".txt")
        || lower.ends_with(".canvas")
        || lower.ends_with(".toml")
        || lower.ends_with(".json")
        || lower.ends_with(".yaml")
        || lower.ends_with(".yml")
}

/// Detect names inside `dir` that differ only by case (folds to the same
/// name on case-insensitive filesystems like macOS/Windows).
/// Returns pairs of conflicting names.
pub fn case_collisions(names: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for i in 0..names.len() {
        for j in (i + 1)..names.len() {
            if names[i] != names[j] && names[i].eq_ignore_ascii_case(&names[j]) {
                out.push((names[i].clone(), names[j].clone()));
            }
        }
    }
    out
}

/// Default sync excludes per spec: cache dir, `.git/`, `.trash/`,
/// `.obsidian/workspace*.json`, OS junk, editor swap files.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    ".git/**",
    ".git",
    ".trash/**",
    ".trash",
    ".obsidian/workspace*.json",
    ".DS_Store",
    "**/.DS_Store",
    "Thumbs.db",
    "**/Thumbs.db",
    "desktop.ini",
    "**/desktop.ini",
    "*.swp",
    "*~",
    ".#*",
    ".stone/trash/**",
];

/// A compiled set of exclusion globs (defaults + `.stone/sync.toml` extras).
#[derive(Debug, Clone)]
pub struct ExcludeSet {
    set: GlobSet,
}

impl Default for ExcludeSet {
    fn default() -> Self {
        Self::from_globs(DEFAULT_EXCLUDES.iter().map(|s| s.to_string()))
    }
}

impl ExcludeSet {
    pub fn from_globs<I: IntoIterator<Item = String>>(globs: I) -> Self {
        let mut b = GlobSetBuilder::new();
        for g in globs {
            if let Ok(glob) = Glob::new(&g) {
                b.add(glob);
            }
        }
        Self {
            set: b.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    /// `extra` lines from `.stone/sync.toml` merged over the defaults.
    pub fn with_extra<I: IntoIterator<Item = String>>(&self, extra: I) -> Self {
        let mut b = GlobSetBuilder::new();
        for g in DEFAULT_EXCLUDES {
            if let Ok(glob) = Glob::new(g) {
                b.add(glob);
            }
        }
        for g in extra {
            if let Ok(glob) = Glob::new(&g) {
                b.add(glob);
            }
        }
        Self {
            set: b.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    pub fn is_excluded(&self, rel: &str) -> bool {
        // Also exclude anything under `.stone/` except explicit synced config
        // files — the cache never syncs, and `.stone` holds only settings.
        if rel.starts_with(".stone/trash") {
            return true;
        }
        self.set.is_match(rel)
    }
}

/// Should this vault-relative path be indexed by the search index?
/// Index covers text-like user content; excluded/hidden paths are skipped.
pub fn indexable(rel: &str) -> bool {
    if !is_text_like(rel) {
        return false;
    }
    for seg in rel.split('/') {
        if seg.starts_with('.') {
            return false;
        }
    }
    true
}

/// Syncable = user content + `.stone/` settings, minus excludes.
pub fn syncable(rel: &str) -> bool {
    ExcludeSet::default().is_excluded(rel) == false
}

/// Split a note reference like `a/b` or `a/b.md` to the canonical form used
/// internally (with or without `.md` depending on call site).
pub fn strip_md(name: &str) -> String {
    let n = normalize_rel(name);
    if n.to_lowercase().ends_with(".md") {
        n[..n.len() - 3].to_string()
    } else {
        n
    }
}

/// Ensure a path has the `.md` extension.
pub fn with_md(name: &str) -> String {
    let n = normalize_rel(name);
    if n.to_lowercase().ends_with(".md") {
        n
    } else {
        format!("{n}.md")
    }
}
