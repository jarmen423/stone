//! Merge engine: token-level 3-way merge (diff3) for prose, key merges for
//! frontmatter / canvas / settings, and conflict copies on real conflicts.
//!
//! Rules (spec):
//! - Markdown body: token-level diff3 against the journal's base. Same spot
//!   changed differently on both sides → keep local, write the remote version
//!   as a conflict copy. Never emit conflict markers.
//! - Frontmatter: merged key by key; same key changed both ways → conflict copy.
//! - `.canvas`: JSON merge by node/edge id.
//! - `.stone/` settings: TOML/JSON key merge.
//! - Binaries: no merge; local stays, remote becomes a conflict copy.

use crate::paths;
use serde_yaml::{Mapping as YamlMap, Value as YamlValue};

#[derive(Debug)]
pub enum MergeOutcome {
    /// Merged cleanly — this is the file content to write.
    Clean(Vec<u8>),
    /// Conflict somewhere: `merged` is the local-preferred result to write at
    /// the real path; `remote` should be saved as a conflict copy.
    Conflicted { merged: Vec<u8>, remote: Vec<u8> },
}

impl MergeOutcome {
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            MergeOutcome::Clean(b) => b,
            MergeOutcome::Conflicted { merged, .. } => merged,
        }
    }
    pub fn had_conflict(&self) -> bool {
        matches!(self, MergeOutcome::Conflicted { .. })
    }
}

/// Entry point: pick the merge rule by file type.
pub fn merge_file(rel_path: &str, base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeOutcome {
    if ours == theirs {
        return MergeOutcome::Clean(ours.to_vec());
    }
    if ours == base {
        return MergeOutcome::Clean(theirs.to_vec());
    }
    if theirs == base {
        return MergeOutcome::Clean(ours.to_vec());
    }

    if paths::is_markdown(rel_path) {
        return merge_markdown(base, ours, theirs);
    }
    if paths::is_canvas(rel_path) {
        return merge_canvas(base, ours, theirs);
    }
    let lower = rel_path.to_lowercase();
    if lower.ends_with(".json") || (lower.starts_with(".stone/") && lower.ends_with(".toml")) {
        return merge_settings(base, ours, theirs);
    }
    if is_utf8(base) && is_utf8(ours) && is_utf8(theirs) {
        return merge_markdown(base, ours, theirs);
    }
    MergeOutcome::Conflicted {
        merged: ours.to_vec(),
        remote: theirs.to_vec(),
    }
}

fn is_utf8(b: &[u8]) -> bool {
    std::str::from_utf8(b).is_ok()
}

// ============================ token diff3 ============================

/// Split text into merge tokens: word runs, single punctuation chars,
/// whitespace runs, and individual newlines (paragraph anchors).
pub fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_kind: Option<u8> = None;
    for ch in text.chars() {
        let kind: u8 = if ch == '\n' {
            3
        } else if ch.is_whitespace() {
            0
        } else if ch.is_alphanumeric() || ch == '_' || ch == '-' {
            1
        } else {
            2
        };
        if kind == 3 {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            cur_kind = None;
            out.push("\n".to_string());
            continue;
        }
        match cur_kind {
            Some(k) if k == kind => cur.push(ch),
            _ => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                cur.push(ch);
                cur_kind = Some(kind);
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Op {
    Equal,
    Delete,
    Insert,
}

#[derive(Debug, Clone)]
struct Hunk {
    base_start: usize,
    base_end: usize,
    new_start: usize,
    new_end: usize,
}

/// Diff base→new as a hunk list (changed regions only).
fn diff_hunks(base: &[u32], new: &[u32]) -> Vec<Hunk> {
    let ops = lcs_ops(base, new);
    let mut hunks = Vec::new();
    let (mut bi, mut ni) = (0usize, 0usize);
    let mut cur: Option<Hunk> = None;
    for (op, len) in ops {
        match op {
            Op::Equal => {
                if let Some(h) = cur.take() {
                    hunks.push(h);
                }
                bi += len;
                ni += len;
            }
            Op::Delete => {
                let h = cur.get_or_insert(Hunk {
                    base_start: bi,
                    base_end: bi,
                    new_start: ni,
                    new_end: ni,
                });
                h.base_end += len;
                bi += len;
            }
            Op::Insert => {
                let h = cur.get_or_insert(Hunk {
                    base_start: bi,
                    base_end: bi,
                    new_start: ni,
                    new_end: ni,
                });
                h.new_end += len;
                ni += len;
            }
        }
    }
    if let Some(h) = cur {
        hunks.push(h);
    }
    hunks
}

/// LCS diff over interned ids → walk of (Op, len).
/// O(NM) memory — fine for notes (a 50 KB note is ~7k tokens; the guard
/// falls back to a coarse diff for absurd inputs).
fn lcs_ops(a: &[u32], b: &[u32]) -> Vec<(Op, usize)> {
    let (nl, ml) = (a.len(), b.len());
    if nl == 0 && ml == 0 {
        return Vec::new();
    }
    if nl == 0 {
        return vec![(Op::Insert, ml)];
    }
    if ml == 0 {
        return vec![(Op::Delete, nl)];
    }
    if nl.saturating_mul(ml) > 64_000_000 {
        return vec![(Op::Delete, nl), (Op::Insert, ml)];
    }
    let width = ml + 1;
    let mut dp = vec![0u32; (nl + 1) * width];
    for i in (0..nl).rev() {
        for j in (0..ml).rev() {
            dp[i * width + j] = if a[i] == b[j] {
                dp[(i + 1) * width + (j + 1)] + 1
            } else {
                dp[(i + 1) * width + j].max(dp[i * width + j + 1])
            };
        }
    }
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < nl && j < ml {
        if a[i] == b[j] {
            push_op(&mut out, Op::Equal, 1);
            i += 1;
            j += 1;
        } else if dp[(i + 1) * width + j] >= dp[i * width + j + 1] {
            push_op(&mut out, Op::Delete, 1);
            i += 1;
        } else {
            push_op(&mut out, Op::Insert, 1);
            j += 1;
        }
    }
    while i < nl {
        push_op(&mut out, Op::Delete, 1);
        i += 1;
    }
    while j < ml {
        push_op(&mut out, Op::Insert, 1);
        j += 1;
    }
    out
}

fn push_op(v: &mut Vec<(Op, usize)>, op: Op, len: usize) {
    if let Some((o, l)) = v.last_mut() {
        if *o == op {
            *l += len;
            return;
        }
    }
    v.push((op, len));
}

fn intern(base: &[String], ours: &[String], theirs: &[String]) -> (Vec<u32>, Vec<u32>, Vec<u32>) {
    let mut map: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut next = 0u32;
    let mut ids = |items: &[String]| -> Vec<u32> {
        items
            .iter()
            .map(|s| {
                if let Some(&id) = map.get(s) {
                    id
                } else {
                    let id = next;
                    map.insert(s.clone(), id);
                    next += 1;
                    id
                }
            })
            .collect()
    };
    let b = ids(base);
    let o = ids(ours);
    let t = ids(theirs);
    (b, o, t)
}

#[derive(Debug, PartialEq)]
pub struct Merge3 {
    /// Merged text with local preference inside conflicted regions.
    pub merged: String,
    /// Number of true conflicts (both sides changed the same region).
    pub conflicts: usize,
}

#[derive(Debug)]
struct Region {
    base_start: usize,
    base_end: usize,
    ours_start: usize,
    ours_end: usize,
    theirs_start: usize,
    theirs_end: usize,
}

/// Cluster hunks from both diffs into regions where base_start ranges overlap.
/// For each region, each side's span in its own token stream is computed;
/// a side with no hunks maps the base range through its cumulative shift.
fn compute_regions(ho: &[Hunk], ht: &[Hunk]) -> Vec<Region> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    // shift = (number of tokens the side has before base position p) - p,
    // accumulated over that side's consumed hunks.
    let mut o_shift: isize = 0;
    let mut t_shift: isize = 0;
    loop {
        let a = ho.get(i);
        let b = ht.get(j);
        if a.is_none() && b.is_none() {
            break;
        }
        let start = match (a, b) {
            (Some(x), Some(y)) => x.base_start.min(y.base_start),
            (Some(x), None) => x.base_start,
            (None, Some(y)) => y.base_start,
            _ => unreachable!(),
        };
        let mut base_end = start;
        let mut o_range: Option<(usize, usize)> = None;
        let mut t_range: Option<(usize, usize)> = None;
        let mut o_absorbed_shift: isize = 0;
        let mut t_absorbed_shift: isize = 0;
        loop {
            let mut grew = false;
            while let Some(x) = ho.get(i) {
                if x.base_start <= base_end {
                    base_end = base_end.max(x.base_end);
                    o_range = Some(match o_range {
                        Some((s, e)) => (s.min(x.new_start), e.max(x.new_end)),
                        None => (x.new_start, x.new_end),
                    });
                    o_absorbed_shift += (x.new_end - x.new_start) as isize
                        - (x.base_end - x.base_start) as isize;
                    i += 1;
                    grew = true;
                } else {
                    break;
                }
            }
            while let Some(y) = ht.get(j) {
                if y.base_start <= base_end {
                    base_end = base_end.max(y.base_end);
                    t_range = Some(match t_range {
                        Some((s, e)) => (s.min(y.new_start), e.max(y.new_end)),
                        None => (y.new_start, y.new_end),
                    });
                    t_absorbed_shift += (y.new_end - y.new_start) as isize
                        - (y.base_end - y.base_start) as isize;
                    j += 1;
                    grew = true;
                } else {
                    break;
                }
            }
            if !grew {
                break;
            }
        }
        // A side that absorbed hunks has its consumed shift already inside its
        // new_* coordinates; the running shift for the pre-region unchanged
        // part is what maps side positions for sides with NO hunks.
        let (os, oe) = match o_range {
            Some(r) => {
                // absorbed hunks' new coords are absolute
                let r = (
                    r.0,
                    r.1,
                );
                o_shift += o_absorbed_shift;
                r
            }
            None => (
                (start as isize + o_shift) as usize,
                (base_end as isize + o_shift) as usize,
            ),
        };
        let (ts, te) = match t_range {
            Some(r) => {
                let r = (r.0, r.1);
                t_shift += t_absorbed_shift;
                r
            }
            None => (
                (start as isize + t_shift) as usize,
                (base_end as isize + t_shift) as usize,
            ),
        };
        out.push(Region {
            base_start: start,
            base_end,
            ours_start: os,
            ours_end: oe,
            theirs_start: ts,
            theirs_end: te,
        });
    }
    out
}

/// Token-level 3-way merge. Local (`ours`) wins conflicted regions.
pub fn diff3_merge(base: &str, ours: &str, theirs: &str) -> Merge3 {
    let base_t = tokenize(base);
    let ours_t = tokenize(ours);
    let theirs_t = tokenize(theirs);
    let (b, o, t) = intern(&base_t, &ours_t, &theirs_t);
    let hunks_o = diff_hunks(&b, &o);
    let hunks_t = diff_hunks(&b, &t);
    let regions = compute_regions(&hunks_o, &hunks_t);

    let mut merged = String::new();
    let mut conflicts = 0usize;
    let mut base_pos = 0usize;
    for r in &regions {
        while base_pos < r.base_start {
            merged.push_str(&base_t[base_pos]);
            base_pos += 1;
        }
        let ours_seg: String = ours_t[r.ours_start..r.ours_end].concat();
        let theirs_seg: String = theirs_t[r.theirs_start..r.theirs_end].concat();
        let base_seg: String = base_t[r.base_start..r.base_end].concat();
        if ours_seg == theirs_seg {
            merged.push_str(&ours_seg);
        } else if theirs_seg == base_seg {
            merged.push_str(&ours_seg);
        } else if ours_seg == base_seg {
            merged.push_str(&theirs_seg);
        } else {
            merged.push_str(&ours_seg);
            conflicts += 1;
        }
        base_pos = r.base_end;
    }
    while base_pos < base_t.len() {
        merged.push_str(&base_t[base_pos]);
        base_pos += 1;
    }
    Merge3 { merged, conflicts }
}

// ============================ frontmatter ============================

/// Split a markdown doc into (frontmatter_map, body_start_offset).
fn split_frontmatter(text: &str) -> (Option<YamlMap>, usize) {
    match crate::parser::parse_frontmatter(text) {
        Some(fm) => {
            let map = fm.value.as_ref().and_then(|v| v.as_mapping().cloned());
            (map, fm.span.end)
        }
        None => (None, 0),
    }
}

/// Merge a markdown file: frontmatter merged key-wise, body via diff3.
fn merge_markdown(base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeOutcome {
    let (Ok(base_s), Ok(ours_s), Ok(theirs_s)) = (
        std::str::from_utf8(base),
        std::str::from_utf8(ours),
        std::str::from_utf8(theirs),
    ) else {
        return MergeOutcome::Conflicted {
            merged: ours.to_vec(),
            remote: theirs.to_vec(),
        };
    };
    let (base_fm, base_body_start) = split_frontmatter(base_s);
    let (ours_fm, ours_body_start) = split_frontmatter(ours_s);
    let (theirs_fm, theirs_body_start) = split_frontmatter(theirs_s);

    let body_merge = diff3_merge(
        &base_s[base_body_start..],
        &ours_s[ours_body_start..],
        &theirs_s[theirs_body_start..],
    );
    let fm_res = merge_yaml_map(
        base_fm.as_ref(),
        ours_fm.as_ref(),
        theirs_fm.as_ref(),
    );
    let had_conflict = body_merge.conflicts > 0 || fm_res.conflict;
    let mut out = String::new();
    if !fm_res.map.is_empty() {
        out.push_str("---\n");
        out.push_str(&serde_yaml::to_string(&YamlValue::Mapping(fm_res.map)).unwrap_or_default());
        out.push_str("---\n");
    }
    out.push_str(&body_merge.merged);
    if had_conflict {
        MergeOutcome::Conflicted {
            merged: out.into_bytes(),
            remote: theirs.to_vec(),
        }
    } else {
        MergeOutcome::Clean(out.into_bytes())
    }
}

struct KeyMergeResult {
    map: YamlMap,
    conflict: bool,
}

/// Key-by-key YAML mapping merge.
fn merge_yaml_map(base: Option<&YamlMap>, ours: Option<&YamlMap>, theirs: Option<&YamlMap>) -> KeyMergeResult {
    let empty = YamlMap::new();
    let b = base.unwrap_or(&empty);
    let o = ours.unwrap_or(&empty);
    let t = theirs.unwrap_or(&empty);
    let mut out = YamlMap::new();
    let mut conflict = false;
    let mut keys: Vec<YamlValue> = o.keys().cloned().collect();
    for k in t.keys().chain(b.keys()) {
        if !keys.contains(k) {
            keys.push(k.clone());
        }
    }
    for k in keys {
        match (b.get(&k), o.get(&k), t.get(&k)) {
            (Some(bv), Some(ov), Some(tv)) => {
                if ov == tv {
                    out.insert(k, ov.clone());
                } else if ov == bv {
                    out.insert(k, tv.clone());
                } else if tv == bv {
                    out.insert(k, ov.clone());
                } else {
                    conflict = true;
                    out.insert(k, ov.clone());
                }
            }
            (Some(bv), Some(ov), None) => {
                if ov != bv {
                    conflict = true;
                    out.insert(k, ov.clone());
                }
            }
            (Some(bv), None, Some(tv)) => {
                if tv != bv {
                    conflict = true;
                    out.insert(k, tv.clone());
                }
            }
            (None, Some(ov), Some(tv)) => {
                if ov == tv {
                    out.insert(k, ov.clone());
                } else {
                    conflict = true;
                    out.insert(k, ov.clone());
                }
            }
            (Some(_), None, None) => {}
            (None, Some(ov), None) => {
                out.insert(k, ov.clone());
            }
            (None, None, Some(tv)) => {
                out.insert(k, tv.clone());
            }
            (None, None, None) => {}
        }
    }
    KeyMergeResult { map: out, conflict }
}

// ============================ canvas & settings (JSON) ============================

fn merge_canvas(base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeOutcome {
    let (Ok(b), Ok(o), Ok(t)) = (
        serde_json::from_slice::<serde_json::Value>(base),
        serde_json::from_slice::<serde_json::Value>(ours),
        serde_json::from_slice::<serde_json::Value>(theirs),
    ) else {
        return MergeOutcome::Conflicted {
            merged: ours.to_vec(),
            remote: theirs.to_vec(),
        };
    };
    let mut conflict = false;
    let merged = merge_json_value(&b, &o, &t, &mut conflict);
    let merged_bytes = serde_json::to_vec_pretty(&merged).unwrap_or_else(|_| ours.to_vec());
    if conflict {
        MergeOutcome::Conflicted {
            merged: merged_bytes,
            remote: theirs.to_vec(),
        }
    } else {
        MergeOutcome::Clean(merged_bytes)
    }
}

/// Generic 3-way JSON merge: objects merge key-wise; arrays of `{id}` objects
/// merge per-id (canvas nodes/edges); anything else conflicts with local wins.
fn merge_json_value(
    base: &serde_json::Value,
    ours: &serde_json::Value,
    theirs: &serde_json::Value,
    conflict: &mut bool,
) -> serde_json::Value {
    use serde_json::Value as V;
    if ours == theirs {
        return ours.clone();
    }
    if ours == base {
        return theirs.clone();
    }
    if theirs == base {
        return ours.clone();
    }
    match (base, ours, theirs) {
        (V::Object(b), V::Object(o), V::Object(t)) => {
            let mut out = serde_json::Map::new();
            let keys: std::collections::BTreeSet<&String> =
                b.keys().chain(o.keys()).chain(t.keys()).collect();
            for k in keys {
                match (b.get(k), o.get(k), t.get(k)) {
                    (Some(bv), Some(ov), Some(tv)) => {
                        out.insert(k.clone(), merge_json_value(bv, ov, tv, conflict));
                    }
                    (Some(bv), Some(ov), None) => {
                        if ov != bv {
                            *conflict = true;
                            out.insert(k.clone(), ov.clone());
                        }
                    }
                    (Some(bv), None, Some(tv)) => {
                        if tv != bv {
                            *conflict = true;
                            out.insert(k.clone(), tv.clone());
                        }
                    }
                    (None, Some(ov), Some(tv)) => {
                        if ov == tv {
                            out.insert(k.clone(), ov.clone());
                        } else {
                            *conflict = true;
                            out.insert(k.clone(), ov.clone());
                        }
                    }
                    (None, Some(ov), None) => {
                        out.insert(k.clone(), ov.clone());
                    }
                    (None, None, Some(tv)) => {
                        out.insert(k.clone(), tv.clone());
                    }
                    _ => {}
                }
            }
            V::Object(out)
        }
        (V::Array(b), V::Array(o), V::Array(t)) => {
            if o.iter().chain(t.iter()).all(|v| {
                v.as_object().map(|m| m.contains_key("id")).unwrap_or(false)
            }) {
                merge_id_array(b, o, t, conflict)
            } else {
                *conflict = true;
                ours.clone()
            }
        }
        _ => {
            *conflict = true;
            ours.clone()
        }
    }
}

fn merge_id_array(
    base: &[serde_json::Value],
    ours: &[serde_json::Value],
    theirs: &[serde_json::Value],
    conflict: &mut bool,
) -> serde_json::Value {
    use serde_json::Value as V;
    fn id_of(v: &V) -> Option<String> {
        v.get("id").and_then(|i| i.as_str().map(String::from))
    }
    fn find<'a>(arr: &'a [serde_json::Value], id: &str) -> Option<&'a serde_json::Value> {
        arr.iter().find(|v| id_of(v).as_deref() == Some(id))
    }
    let mut ids: Vec<String> = Vec::new();
    for v in ours.iter().chain(theirs.iter()) {
        if let Some(id) = id_of(v) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
    }
    let mut out = Vec::new();
    for id in ids {
        match (find(base, &id), find(ours, &id), find(theirs, &id)) {
            (Some(bv), Some(ov), Some(tv)) => {
                out.push(merge_json_value(bv, ov, tv, conflict));
            }
            (Some(bv), Some(ov), None) => {
                if ov != bv {
                    *conflict = true;
                    out.push(ov.clone());
                }
            }
            (Some(bv), None, Some(tv)) => {
                if tv != bv {
                    *conflict = true;
                    out.push(tv.clone());
                }
            }
            (None, Some(ov), Some(tv)) => {
                if ov == tv {
                    out.push(ov.clone());
                } else {
                    *conflict = true;
                    out.push(ov.clone());
                }
            }
            (None, Some(ov), None) => out.push(ov.clone()),
            (None, None, Some(tv)) => out.push(tv.clone()),
            _ => {}
        }
    }
    V::Array(out)
}

fn merge_settings(base: &[u8], ours: &[u8], theirs: &[u8]) -> MergeOutcome {
    if let (Some(b), Some(o), Some(t)) = (
        try_parse_setting(base),
        try_parse_setting(ours),
        try_parse_setting(theirs),
    ) {
        let mut conflict = false;
        let merged = merge_json_value(&b, &o, &t, &mut conflict);
        let bytes = serde_json::to_vec_pretty(&merged).unwrap_or_else(|_| ours.to_vec());
        return if conflict {
            MergeOutcome::Conflicted {
                merged: bytes,
                remote: theirs.to_vec(),
            }
        } else {
            MergeOutcome::Clean(bytes)
        };
    }
    MergeOutcome::Conflicted {
        merged: ours.to_vec(),
        remote: theirs.to_vec(),
    }
}

fn try_parse_setting(b: &[u8]) -> Option<serde_json::Value> {
    let s = std::str::from_utf8(b).ok()?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(s) {
        return Some(v);
    }
    if let Ok(v) = toml::from_str::<toml::Value>(s) {
        return serde_json::to_value(v).ok();
    }
    None
}

/// Conflict-copy filename: `Note (conflict <device> <YYYY-MM-DD HHmm>).md`.
pub fn conflict_name(rel_path: &str, device: &str, ts: chrono::DateTime<chrono::Utc>) -> String {
    let stem = crate::links::strip_ext(crate::links::basename(rel_path));
    let dir = match rel_path.rfind('/') {
        Some(i) => &rel_path[..i + 1],
        None => "",
    };
    let ext = match rel_path.rfind('.') {
        Some(i) if i > rel_path.rfind('/').map(|x| x + 1).unwrap_or(0) => &rel_path[i..],
        _ => "",
    };
    let device = device.replace(['/', '\\', ':'], "-");
    format!(
        "{dir}{stem} (conflict {device} {}){}",
        ts.format("%Y-%m-%d %H%M"),
        ext
    )
}
