//! Link resolution matching Obsidian's rules, and surgical link rewriting.
//!
//! Resolution rules implemented:
//! - `[[a/b]]` resolves to vault-relative `a/b.md` first, then to any path
//!   ending in `/a/b.md`, then to basename match.
//! - `[[Note]]` resolves to any note with basename `Note`, preferring the
//!   shortest path; ties are ambiguous.
//! - Aliases from frontmatter participate like basenames.
//! - Links keep their spelling; a rename rewrites only the target bytes.

use crate::error::{Result, StoneError};
use crate::parser::{self, ParsedNote, Wikilink};
use crate::paths;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A note's identity for link resolution.
#[derive(Debug, Clone)]
pub struct NoteMeta {
    /// Vault-relative path WITH extension, e.g. `a/b/Note.md`.
    pub path: String,
    /// Aliases from frontmatter.
    pub aliases: Vec<String>,
    /// Block ids defined in the note.
    pub block_ids: BTreeSet<String>,
    /// Heading texts (`[[Note#Heading]]` resolution).
    pub headings: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub struct VaultLinks {
    /// path -> meta
    pub notes: BTreeMap<String, NoteMeta>,
}

impl VaultLinks {
    /// Build from parsed notes: iterator of (path, parsed).
    pub fn build<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (&'a str, &'a ParsedNote)>,
    {
        let mut notes = BTreeMap::new();
        for (path, parsed) in iter {
            let path = paths::normalize_rel(path);
            notes.insert(
                path.clone(),
                NoteMeta {
                    path,
                    aliases: parsed.aliases(),
                    block_ids: parsed.block_ids.iter().map(|b| b.id.clone()).collect(),
                    headings: parsed.headings.iter().map(|h| h.text.clone()).collect(),
                },
            );
        }
        Self { notes }
    }

    /// Does a path exist as a note or attachment (basename lookup covers
    /// `![[img.png]]` embeds too — attachments are included if registered).
    pub fn contains(&self, path: &str) -> bool {
        self.notes.contains_key(&paths::normalize_rel(path))
    }

    /// Register a non-note file (attachment) so embeds resolve.
    pub fn add_file(&mut self, path: &str) {
        let path = paths::normalize_rel(path);
        self.notes.entry(path.clone()).or_insert_with(|| NoteMeta {
            path,
            aliases: Vec::new(),
            block_ids: BTreeSet::new(),
            headings: BTreeSet::new(),
        });
    }

    /// Resolve a link target to a vault path.
    /// Returns Ok(Some(path)), Ok(None) for unresolved, Err(AmbiguousLink) on ties.
    pub fn resolve(&self, target: &str) -> Result<Option<String>> {
        let cands = self.candidates(target);
        match cands.len() {
            0 => Ok(None),
            1 => Ok(Some(cands.into_iter().next().unwrap())),
            _ => {
                // shortest unique path: pick candidates of minimal length
                let mut v: Vec<String> = cands.into_iter().collect();
                v.sort_by_key(|s| (s.len(), s.clone()));
                let min = v[0].len();
                let shortest: Vec<String> =
                    v.iter().filter(|s| s.len() == min).cloned().collect();
                if shortest.len() == 1 {
                    return Ok(Some(shortest.into_iter().next().unwrap()));
                }
                Err(StoneError::AmbiguousLink(
                    target.to_string(),
                    shortest.join(", "),
                ))
            }
        }
    }

    /// All plausible resolution targets for a link string.
    pub fn candidates(&self, target: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let t = paths::normalize_rel(target);
        if t.is_empty() {
            return out;
        }
        let t_md = paths::with_md(&t);
        let has_slash = t.contains('/');
        let has_ext = has_extension(&t);

        for p in self.notes.keys() {
            if !has_ext {
                // match against note path without extension too
                if *p == t_md || strip_ext(p) == t {
                    out.insert(p.clone());
                    continue;
                }
                if has_slash && (p.ends_with(&format!("/{t_md}")) || strip_ext(p).ends_with(&format!("/{t}"))) {
                    out.insert(p.clone());
                    continue;
                }
            } else {
                // attachments and explicitly extensioned notes: exact or suffix
                if *p == t || p.ends_with(&format!("/{t}")) {
                    out.insert(p.clone());
                    continue;
                }
            }
            // basename / alias match (bare links only)
            if !has_slash && !has_ext {
                let stem = strip_ext(basename(p));
                if stem == t {
                    out.insert(p.clone());
                    continue;
                }
            }
        }
        // alias pass
        if !has_slash && !has_ext {
            for (p, meta) in &self.notes {
                if meta.aliases.iter().any(|a| a == &t) {
                    out.insert(p.clone());
                }
            }
        }
        out
    }

    /// When `target` resolves ambiguously, find the shortest spelling that
    /// uniquely names ONE candidate — the one the bare spelling most plausibly
    /// meant (first alphabetically of the shortest candidates).
    /// Returns None when nothing disambiguates (kept as-is by callers).
    pub fn minimal_target_ambiguous(&self, target: &str) -> Option<String> {
        let cands = self.candidates(target);
        if cands.len() < 2 {
            return None;
        }
        // canonical pick: shortest, then alphabetical
        let mut v: Vec<String> = cands.iter().cloned().collect();
        v.sort_by_key(|s| (s.len(), s.clone()));
        let min = v[0].len();
        let shortest: Vec<&String> = v.iter().filter(|s| s.len() == min).collect();
        let chosen = shortest[0];
        Some(self.minimal_target(chosen))
    }

    /// The shortest unambiguous spelling for a link to `target_path` —
    /// basename if unique, else the shortest unique vault-relative suffix.
    pub fn minimal_target(&self, target_path: &str) -> String {
        let target_path = paths::normalize_rel(target_path);
        let stem = strip_ext(basename(&target_path));
        // bare basename unique?
        let bare_matches = self
            .notes
            .keys()
            .filter(|p| strip_ext(basename(p)) == stem)
            .count();
        if bare_matches == 1 {
            return stem.to_string();
        }
        // extend with parent dirs until unique
        let parts: Vec<&str> = target_path.split('/').collect();
        for k in 1..=parts.len() {
            let suffix = parts[parts.len() - k..].join("/");
            let suffix_noext = strip_ext(&suffix);
            let matches = self
                .notes
                .keys()
                .filter(|p| {
                    *p == &suffix
                        || p.ends_with(&format!("/{suffix}"))
                        || strip_ext(p) == suffix_noext
                        || strip_ext(p).ends_with(&format!("/{suffix_noext}"))
                })
                .count();
            if matches == 1 {
                return suffix_noext.to_string();
            }
        }
        strip_ext(&target_path).to_string()
    }
}

pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

pub fn strip_ext(path: &str) -> &str {
    match path.rfind('.') {
        Some(i) if i > path.rfind('/').map(|x| x + 1).unwrap_or(0) => &path[..i],
        _ => path,
    }
}

pub fn has_extension(path: &str) -> bool {
    let base = basename(path);
    base.rfind('.').map(|i| i > 0).unwrap_or(false)
}

/// A planned surgical edit: replace `span` bytes in `path` with `replacement`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkEdit {
    pub path: String,
    pub span_start: usize,
    pub span_end: usize,
    pub old_text: String,
    pub new_text: String,
}

/// Plan link rewrites for a rename/move of `old_path` → `new_path`.
///
/// Returns per-file edits (multiple per file possible). Caller must apply
/// edits from END to START of each file to keep spans valid.
///
/// `docs`: map of path → full text of every file containing candidate links.
/// `links`: the vault link index BEFORE the move (still contains old path).
pub fn plan_rename_rewrites(
    links: &VaultLinks,
    docs: &BTreeMap<String, String>,
    old_path: &str,
    new_path: &str,
) -> Result<BTreeMap<String, Vec<LinkEdit>>> {
    let old_path = paths::normalize_rel(old_path);
    let new_path = paths::normalize_rel(new_path);
    let mut out: BTreeMap<String, Vec<LinkEdit>> = BTreeMap::new();

    // The post-move namespace: remove old, add new.
    let mut post = links.clone();
    if let Some(meta) = post.notes.remove(&old_path) {
        let mut m = meta;
        m.path = new_path.clone();
        post.notes.insert(new_path.clone(), m);
    }

    let new_stem = strip_ext(basename(&new_path)).to_string();
    let old_stem = strip_ext(basename(&old_path)).to_string();
    let stem_changed = new_stem != old_stem;

    for (path, text) in docs {
        let parsed = parser::parse(text);
        let mut edits: Vec<LinkEdit> = Vec::new();
        for link in parsed.links.iter().filter(|l| !l.embed) {
            let resolved_old = links.resolve(&link.target).ok().flatten();
            if resolved_old.as_deref() == Some(old_path.as_str()) {
                // This link pointed at the moved file — retarget it.
                let new_target = retarget(&post, link, &new_path);
                if new_target != link.target {
                    edits.push(LinkEdit {
                        path: path.clone(),
                        span_start: link.target_span.start,
                        span_end: link.target_span.end,
                        old_text: link.target.clone(),
                        new_text: new_target,
                    });
                }
            } else if stem_changed {
                // Link might now be ambiguous or pointing at wrong file due to
                // the rename changing the basename namespace.
                let resolved_new = post.resolve(&link.target).ok().flatten();
                match (resolved_old, resolved_new) {
                    (Some(before), Some(after)) if before != after => {
                        // The rename hijacked this link to a different note;
                        // qualify the spelling to keep it on the original target.
                        let qualified = post.minimal_target(&before);
                        if qualified != link.target {
                            edits.push(LinkEdit {
                                path: path.clone(),
                                span_start: link.target_span.start,
                                span_end: link.target_span.end,
                                old_text: link.target.clone(),
                                new_text: qualified,
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        // embeds also rewrite (image targets move too)
        for link in parsed.links.iter().filter(|l| l.embed) {
            let resolved_old = links.resolve(&link.target).ok().flatten();
            if resolved_old.as_deref() == Some(old_path.as_str()) {
                let new_target = retarget(&post, link, &new_path);
                if new_target != link.target {
                    edits.push(LinkEdit {
                        path: path.clone(),
                        span_start: link.target_span.start,
                        span_end: link.target_span.end,
                        old_text: link.target.clone(),
                        new_text: new_target,
                    });
                }
            }
        }
        // sort edits by descending span start so application stays valid
        edits.sort_by_key(|e| std::cmp::Reverse(e.span_start));
        if !edits.is_empty() {
            out.insert(path.clone(), edits);
        }
    }
    Ok(out)
}

/// Choose the new spelling for a link that pointed at the moved note.
/// Keeps the link's existing qualification level: bare stays bare when the
/// new basename is unique; path-qualified links get the minimal unique suffix.
fn retarget(post: &VaultLinks, link: &Wikilink, new_path: &str) -> String {
    let new_stem = strip_ext(basename(new_path)).to_string();
    if !link.path_qualified {
        let bare_matches = post
            .notes
            .keys()
            .filter(|p| strip_ext(basename(p)) == new_stem)
            .count();
        if bare_matches <= 1 {
            return new_stem;
        }
    }
    post.minimal_target(new_path)
}

/// Apply planned edits to a document. Edits must be sorted descending by
/// span start (what `plan_rename_rewrites` returns).
pub fn apply_edits(text: &str, edits: &[LinkEdit]) -> String {
    let mut out = text.to_string();
    for e in edits {
        if e.span_end <= out.len() && out.is_char_boundary(e.span_start) && out.is_char_boundary(e.span_end) {
            out.replace_range(e.span_start..e.span_end, &e.new_text);
        }
    }
    out
}

/// After a rename, find links that became ambiguous (resolve to multiple
/// candidates) — spec requires detecting AND fixing them.
pub fn find_ambiguous_links(
    links: &VaultLinks,
    docs: &BTreeMap<String, String>,
) -> Vec<(String, Wikilink, String)> {
    let mut out = Vec::new();
    for (path, text) in docs {
        let parsed = parser::parse(text);
        for link in parsed.links {
            if let Err(StoneError::AmbiguousLink(_, cands)) = links.resolve(&link.target) {
                out.push((path.clone(), link, cands));
            }
        }
    }
    out
}
