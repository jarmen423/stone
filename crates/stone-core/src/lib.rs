//! stone-core: the single implementation behind the `stone` CLI, the daemon,
//! `stone mcp`, and (later) the desktop/mobile apps.
//!
//! Module map:
//! - `paths`     — vault-relative path normalization (NFC) + exclude rules
//! - `config`    — `.stone/` settings, vault registry, cache-dir layout
//! - `parser`    — Markdown scan with byte spans (wikilinks, embeds, tags,
//!                 tasks, headings, block ids, YAML frontmatter)
//! - `links`     — Obsidian-compatible link resolution + surgical rewrites
//! - `index`     — SQLite (WAL) + FTS5 index in the cache dir
//! - `journal`   — crash-safe SQLite sync journal (merge base per path)
//! - `merge`     — token-level diff3, frontmatter/canvas/settings merges
//! - `crypto`    — vault key, XChaCha20-Poly1305, Argon2id wrap, recovery key
//! - `chunk`     — FastCDC chunking for dedup/resumable uploads
//! - `sync`      — wire protocol + sync agent (pull, merge, CAS commit)
//! - `engine`    — every vault operation (the only write path)
//! - `watcher`   — file watcher with settle window + echo suppression
//! - `daemon`    — loopback JSON-RPC daemon the CLI forwards to
//! - `registry`  — the one command registry (CLI, MCP, palette)
//! - `frontmatter`, `templating` — surgical property edits, `{{date}}` templates

pub mod chunk;
pub mod config;
pub mod crypto;
pub mod daemon;
pub mod engine;
pub mod error;
pub mod frontmatter;
pub mod index;
pub mod journal;
pub mod links;
pub mod merge;
pub mod parser;
pub mod paths;
pub mod registry;
pub mod sync;
pub mod templating;
pub mod watcher;

pub use engine::Engine;
pub use error::{ExitCode, Result, StoneError};
