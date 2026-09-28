//! Markdown scanning with byte spans.
//!
//! `pulldown-cmark` provides block structure and code spans (which we must NOT
//! scan for wikilinks/tags); a custom scanner extracts Obsidian constructs:
//! wikilinks, embeds, block IDs, tags, tasks, headings and YAML frontmatter.
//! Every returned item keeps its byte span so rewrites can edit exactly those
//! bytes and never re-render the document.

use crate::paths;
use pulldown_cmark::{Options, Parser};
use serde_yaml::Value as YamlValue;
use std::ops::Range;

#[derive(Debug, Clone, PartialEq)]
pub struct Wikilink {
    /// Full `[[...]]`/`![[...]]` span.
    pub span: Range<usize>,
    /// Span of just the note path inside the brackets (surgical rewrite target).
    pub target_span: Range<usize>,
    /// The raw inner text, e.g. `Note#head|alias`.
    pub inner: String,
    /// Note path portion (normalized, no extension handling yet).
    pub target: String,
    pub alias: Option<String>,
    pub heading: Option<String>,
    pub block: Option<String>,
    pub embed: bool,
    /// True when the target contains a `/` (path-qualified link).
    pub path_qualified: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    /// `#project/alpha`
    pub name: String,
    pub span: Range<usize>,
    pub from_frontmatter: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    /// `- [ ] text` / `- [x] text`
    pub done: bool,
    pub text: String,
    /// 0-based line number.
    pub line: usize,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Heading {
    pub level: u8,
    pub text: String,
    /// 0-based line number.
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct BlockId {
    pub id: String,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct Frontmatter {
    /// Byte span of the `---...---` block including fences.
    pub span: Range<usize>,
    /// Parsed YAML (None if unparseable — treated as opaque).
    pub value: Option<YamlValue>,
    /// Raw inner YAML text (without fences).
    pub raw: String,
}

#[derive(Debug, Default)]
pub struct ParsedNote {
    pub frontmatter: Option<Frontmatter>,
    pub links: Vec<Wikilink>,
    pub tags: Vec<Tag>,
    pub tasks: Vec<Task>,
    pub headings: Vec<Heading>,
    pub block_ids: Vec<BlockId>,
}

impl ParsedNote {
    /// Property value from frontmatter by key.
    pub fn prop(&self, key: &str) -> Option<&YamlValue> {
        self.frontmatter
            .as_ref()?
            .value
            .as_ref()?
            .as_mapping()?
            .get(YamlValue::String(key.to_string()))
    }

    /// `aliases` from frontmatter.
    pub fn aliases(&self) -> Vec<String> {
        match self.prop("aliases") {
            Some(YamlValue::Sequence(seq)) => seq
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(YamlValue::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }

    /// `tags` from frontmatter (merged with body tags by the index layer).
    pub fn frontmatter_tags(&self) -> Vec<String> {
        match self.prop("tags") {
            Some(YamlValue::Sequence(seq)) => seq
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(YamlValue::String(s)) => s
                .split_whitespace()
                .map(|t| t.trim_start_matches('#').to_string())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// First H1 text, else file-stem is used by callers.
    pub fn title(&self) -> Option<String> {
        self.headings
            .iter()
            .find(|h| h.level == 1)
            .map(|h| h.text.clone())
    }
}

/// Parse a note's markdown.
pub fn parse(text: &str) -> ParsedNote {
    let mut out = ParsedNote::default();
    out.frontmatter = parse_frontmatter(text);
    let code = code_ranges(text);
    scan_wikilinks(text, &code, &mut out);
    scan_tags(text, &code, &mut out);
    scan_tasks_headings_blocks(text, &code, &mut out);
    merge_frontmatter_tags(&mut out);
    out
}

// ---------- frontmatter ----------

/// Frontmatter = `---` on line 0, next `---` or `...` line closes.
pub fn parse_frontmatter(text: &str) -> Option<Frontmatter> {
    let bytes = text.as_bytes();
    if !text.starts_with("---\n") && !text.starts_with("---\r\n") {
        return None;
    }
    let start_inner = if text.starts_with("---\r\n") { 5 } else { 4 };
    // find closing fence
    let mut pos = start_inner;
    for line in text[start_inner..].split_inclusive('\n') {
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            let end = pos + line.len();
            let raw = &text[start_inner..pos];
            let value = serde_yaml::from_str::<YamlValue>(raw).ok();
            let _ = bytes;
            return Some(Frontmatter {
                span: 0..end,
                value,
                raw: raw.to_string(),
            });
        }
        pos += line.len();
    }
    None
}

// ---------- code ranges (never scan inside) ----------

/// Byte ranges occupied by code (fenced blocks + inline code), where
/// wikilinks/tags/comments must not be scanned.
pub fn code_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut in_block = false;
    let mut block_start = 0usize;
    let parser = Parser::new_ext(text, Options::all());
    for (ev, range) in parser.into_offset_iter() {
        match ev {
            pulldown_cmark::Event::Start(pulldown_cmark::Tag::CodeBlock(_)) => {
                in_block = true;
                block_start = range.start;
            }
            pulldown_cmark::Event::End(pulldown_cmark::TagEnd::CodeBlock) => {
                in_block = false;
                ranges.push(block_start..range.end);
            }
            pulldown_cmark::Event::Code(_) => {
                if !in_block {
                    ranges.push(range);
                }
            }
            _ => {}
        }
    }
    ranges
}

fn in_ranges(ranges: &[Range<usize>], pos: usize) -> bool {
    ranges.iter().any(|r| pos >= r.start && pos < r.end)
}

// ---------- wikilinks & embeds ----------

fn scan_wikilinks(text: &str, code: &[Range<usize>], out: &mut ParsedNote) {
    let b = text.as_bytes();
    let mut i = 0usize;
    while i + 1 < b.len() {
        if in_ranges(code, i) {
            i += 1;
            continue;
        }
        let embed = b[i] == b'!'
            && i + 1 < b.len()
            && b[i + 1] == b'['
            && i + 2 < b.len()
            && b[i + 2] == b'[';
        let plain = b[i] == b'[' && b[i + 1] == b'[';
        if !embed && !plain {
            i += 1;
            continue;
        }
        // don't treat `![[` inside `![[` weirdly; also skip `[[` preceded by `[` or `!` already consumed
        let open_end = if embed { i + 3 } else { i + 2 };
        if embed && i > 0 && b[i - 1] == b'[' {
            i += 1;
            continue;
        }
        // find `]]`
        let mut j = open_end;
        let mut found = None;
        while j + 1 < b.len() {
            if b[j] == b']' && b[j + 1] == b']' {
                found = Some(j);
                break;
            }
            if b[j] == b'\n' {
                break;
            }
            j += 1;
        }
        let Some(close) = found else {
            i += 1;
            continue;
        };
        let inner = &text[open_end..close];
        if inner.is_empty() || inner.len() > 4096 {
            i += 1;
            continue;
        }
        // reject markdown-style `[[a](b)]` — inner containing "](" mid-way
        let span_end = close + 2;
        if let Some(wl) = parse_wikilink_inner(text, i, span_end, open_end, inner, embed) {
            out.links.push(wl);
        }
        i = span_end;
    }
}

/// Parse `inner` (between `[[` and `]]`) into target/heading/block/alias.
/// Obsidian grammar: `path#heading#^block|alias` — alias after first `|`,
/// block anchor `^id` only as a `#^id` segment.
fn parse_wikilink_inner(
    text: &str,
    span_start: usize,
    span_end: usize,
    open_end: usize,
    inner: &str,
    embed: bool,
) -> Option<Wikilink> {
    let (lhs, alias) = match inner.find('|') {
        Some(p) => (&inner[..p], Some(inner[p + 1..].to_string())),
        None => (inner, None),
    };
    // split lhs on '#': first part = path, rest = heading/block segments
    let mut parts = lhs.splitn(2, '#');
    let path_part = parts.next().unwrap_or("");
    let mut heading = None;
    let mut block = None;
    if let Some(rest) = parts.next() {
        for seg in rest.split('#') {
            if let Some(bid) = seg.strip_prefix('^') {
                block = Some(bid.to_string());
            } else if !seg.is_empty() {
                heading = Some(match heading {
                    Some(h) => format!("{h}#{seg}"),
                    None => seg.to_string(),
                });
            }
        }
    }
    let target_offset = span_start + if embed { 3 } else { 2 };
    let target_span = target_offset..target_offset + path_part.len();
    let _ = text;
    let _ = open_end;
    Some(Wikilink {
        span: span_start..span_end,
        target_span,
        inner: inner.to_string(),
        target: paths::normalize_rel(path_part),
        alias,
        heading,
        block,
        embed,
        path_qualified: path_part.contains('/'),
    })
}

// ---------- tags ----------

fn is_tag_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-' || c == b'/'
}

/// `#tag` and nested `#a/b` outside code spans. A `#` must be at a word
/// boundary (start of line or after a non-word char); the name must contain
/// at least one non-digit (Obsidian rejects purely numeric tags).
fn scan_tags(text: &str, code: &[Range<usize>], out: &mut ParsedNote) {
    let b = text.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'#' && !in_ranges(code, i) {
            let prev_ok = i == 0
                || !(b[i - 1].is_ascii_alphanumeric() || matches!(b[i - 1], b'_' | b'-' | b'/' | b'[' | b'!'));
            if prev_ok {
                let mut j = i + 1;
                while j < b.len() && is_tag_char(b[j]) {
                    j += 1;
                }
                let name = &text[i + 1..j];
                let name = name.trim_end_matches('/');
                if !name.is_empty() && name.bytes().any(|c| !c.is_ascii_digit()) {
                    out.tags.push(Tag {
                        name: name.to_string(),
                        span: i..i + 1 + name.len(),
                        from_frontmatter: false,
                    });
                }
                i = j.max(i + 1);
                continue;
            }
        }
        i += 1;
    }
}

fn merge_frontmatter_tags(out: &mut ParsedNote) {
    let Some(fm) = out.frontmatter.as_ref() else { return };
    for t in out.frontmatter_tags() {
        out.tags.push(Tag {
            name: t,
            span: fm.span.clone(),
            from_frontmatter: true,
        });
    }
}

// ---------- tasks / headings / block ids (line scanning) ----------

fn scan_tasks_headings_blocks(text: &str, code: &[Range<usize>], out: &mut ParsedNote) {
    let mut line_no = 0usize;
    let mut pos = 0usize;
    for line in text.split_inclusive('\n') {
        let start = pos;
        pos += line.len();
        let content = line.trim_end_matches(['\n', '\r']);
        let in_code = in_ranges(code, start);
        line_no += 1;
        if in_code {
            continue;
        }
        let lno = line_no - 1;
        // heading
        let trimmed_start = content.trim_start();
        if trimmed_start.starts_with('#') {
            let hashes = trimmed_start.bytes().take_while(|&c| c == b'#').count();
            if hashes >= 1 && hashes <= 6 && trimmed_start.as_bytes().get(hashes) == Some(&b' ') {
                out.headings.push(Heading {
                    level: hashes as u8,
                    text: trimmed_start[hashes + 1..].trim().to_string(),
                    line: lno,
                });
            }
        }
        // task: optional indent + `- [ ]` or `- [x]`
        let t = content.trim_start();
        if t.len() >= 5 && (t.starts_with("-") || t.starts_with("*") || t.starts_with("+")) {
            let after = t[1..].trim_start();
            if after.len() >= 4
                && after.as_bytes()[0] == b'['
                && (after.as_bytes()[1] == b' ' || after.as_bytes()[1] == b'x' || after.as_bytes()[1] == b'X')
                && after.as_bytes()[2] == b']'
                && after.as_bytes()[3] == b' '
            {
                let done = after.as_bytes()[1] != b' ';
                let text_part = after[4..].to_string();
                let offset = start + (content.len() - t.len()) + (t.len() - after.len());
                out.tasks.push(Task {
                    done,
                    text: text_part,
                    line: lno,
                    span: offset..offset + after.len(),
                });
            }
        }
        // block id: trailing ` ^id` at end of line
        if let Some(sp) = content.rfind(" ^") {
            let cand = &content[sp + 2..];
            if !cand.is_empty()
                && cand.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            {
                out.block_ids.push(BlockId {
                    id: cand.to_string(),
                    line: lno,
                });
            }
        }
    }
}
