//! One command registry. CLI subcommands, MCP tools, the GUI command palette
//! and the daemon's RPC surface are all generated from this table, so nothing
//! is GUI-only or CLI-only by accident.

use crate::engine::Engine;
use crate::error::{Result, StoneError};
use crate::index::SearchQuery;
use crate::sync::{self, SyncAgent};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

/// Argument kinds for registry-driven surfaces.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ArgKind {
    Positional,
    Option,
    Flag,
}

#[derive(Debug, Clone)]
pub struct ArgSpec {
    pub name: &'static str,
    pub kind: ArgKind,
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub name: &'static str,
    pub summary: &'static str,
    pub args: &'static [ArgSpec],
    /// Whether it changes vault files (CLI exposes --dry-run on these).
    pub mutates: bool,
    /// Exposed as an MCP tool (`stone mcp` exposes a small safe subset).
    pub mcp: bool,
}

const P_NOTE: ArgSpec = ArgSpec {
    name: "note",
    kind: ArgKind::Positional,
    required: true,
};
const P_QUERY: ArgSpec = ArgSpec {
    name: "query",
    kind: ArgKind::Positional,
    required: true,
};

pub fn commands() -> Vec<CommandSpec> {
    use ArgKind::*;
    vec![
        CommandSpec { name: "cat", summary: "Print a note", args: &[P_NOTE], mutates: false, mcp: true },
        CommandSpec { name: "new", summary: "Create a note", args: &[
            ArgSpec { name: "name", kind: Positional, required: true },
            ArgSpec { name: "content", kind: Option, required: false },
            ArgSpec { name: "template", kind: Option, required: false },
        ], mutates: true, mcp: true },
        CommandSpec { name: "append", summary: "Append text to a note", args: &[
            P_NOTE, ArgSpec { name: "text", kind: Option, required: false },
        ], mutates: true, mcp: true },
        CommandSpec { name: "prepend", summary: "Prepend text to a note", args: &[
            P_NOTE, ArgSpec { name: "text", kind: Option, required: false },
        ], mutates: true, mcp: true },
        CommandSpec { name: "edit", summary: "Find/replace inside a note", args: &[
            P_NOTE,
            ArgSpec { name: "find", kind: Option, required: true },
            ArgSpec { name: "replace", kind: Option, required: true },
            ArgSpec { name: "all", kind: Flag, required: false },
        ], mutates: true, mcp: false },
        CommandSpec { name: "mv", summary: "Move/rename a note, rewriting backlinks", args: &[
            ArgSpec { name: "from", kind: Positional, required: true },
            ArgSpec { name: "to", kind: Positional, required: true },
        ], mutates: true, mcp: true },
        CommandSpec { name: "rm", summary: "Move a note to trash", args: &[P_NOTE], mutates: true, mcp: false },
        CommandSpec { name: "daily", summary: "Open/create today's daily note", args: &[
            ArgSpec { name: "date", kind: Option, required: false },
            ArgSpec { name: "append", kind: Option, required: false },
        ], mutates: true, mcp: true },
        CommandSpec { name: "search", summary: "Full-text + structured search", args: &[
            P_QUERY, ArgSpec { name: "limit", kind: Option, required: false },
        ], mutates: false, mcp: true },
        CommandSpec { name: "links", summary: "Outgoing links from a note", args: &[P_NOTE], mutates: false, mcp: false },
        CommandSpec { name: "backlinks", summary: "Notes linking to a note", args: &[P_NOTE], mutates: false, mcp: true },
        CommandSpec { name: "unresolved", summary: "Links that resolve to nothing", args: &[
            ArgSpec { name: "note", kind: Positional, required: false },
        ], mutates: false, mcp: false },
        CommandSpec { name: "orphans", summary: "Notes with no incoming links", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "tags", summary: "All tags with counts", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "tasks", summary: "List tasks", args: &[
            ArgSpec { name: "open", kind: Flag, required: false },
        ], mutates: false, mcp: true },
        CommandSpec { name: "props get", summary: "Read a frontmatter property", args: &[
            P_NOTE, ArgSpec { name: "key", kind: Positional, required: true },
        ], mutates: false, mcp: false },
        CommandSpec { name: "props set", summary: "Set a frontmatter property", args: &[
            P_NOTE,
            ArgSpec { name: "key", kind: Positional, required: true },
            ArgSpec { name: "value", kind: Positional, required: true },
        ], mutates: true, mcp: true },
        CommandSpec { name: "props query", summary: "Find notes by property", args: &[
            ArgSpec { name: "key", kind: Positional, required: true },
            ArgSpec { name: "value", kind: Positional, required: false },
        ], mutates: false, mcp: false },
        CommandSpec { name: "graph", summary: "Note link graph (dot|json)", args: &[
            ArgSpec { name: "format", kind: Option, required: false },
        ], mutates: false, mcp: false },
        CommandSpec { name: "reindex", summary: "Rebuild the index", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "trash list", summary: "List trashed files", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "trash restore", summary: "Restore a trashed file", args: &[
            ArgSpec { name: "name", kind: Positional, required: true },
            ArgSpec { name: "dest", kind: Positional, required: true },
        ], mutates: true, mcp: false },
        CommandSpec { name: "sync setup", summary: "Configure encrypted sync", args: &[
            ArgSpec { name: "server", kind: Option, required: true },
            ArgSpec { name: "device", kind: Option, required: false },
            ArgSpec { name: "password", kind: Option, required: true },
        ], mutates: true, mcp: false },
        CommandSpec { name: "sync invite", summary: "Mint a device token for another machine", args: &[
            ArgSpec { name: "device", kind: Option, required: false },
        ], mutates: true, mcp: false },
        CommandSpec { name: "sync join", summary: "Onboard this device with an invite token", args: &[
            ArgSpec { name: "server", kind: Option, required: true },
            ArgSpec { name: "vault_id", kind: Option, required: true },
            ArgSpec { name: "token", kind: Option, required: true },
            ArgSpec { name: "password", kind: Option, required: true },
            ArgSpec { name: "device", kind: Option, required: false },
        ], mutates: true, mcp: false },
        CommandSpec { name: "sync status", summary: "Sync state", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "sync now", summary: "Run one sync cycle", args: &[
            ArgSpec { name: "force", kind: Flag, required: false },
        ], mutates: true, mcp: false },
        CommandSpec { name: "sync conflicts", summary: "List conflict copies", args: &[], mutates: false, mcp: false },
        CommandSpec { name: "sync history", summary: "Version history for a note", args: &[P_NOTE], mutates: false, mcp: false },
        CommandSpec { name: "sync restore", summary: "Restore a version of a note", args: &[
            P_NOTE, ArgSpec { name: "version", kind: Option, required: true },
        ], mutates: true, mcp: false },
    ]
}

/// MCP tool list (subset of the registry marked `mcp: true`).
pub fn mcp_tools() -> Vec<Value> {
    commands()
        .iter()
        .filter(|c| c.mcp)
        .map(|c| {
            let mut props = serde_json::Map::new();
            let mut required = Vec::new();
            for a in c.args {
                let ty = match a.kind {
                    ArgKind::Flag => "boolean",
                    _ => "string",
                };
                props.insert(a.name.to_string(), json!({"type": ty}));
                if a.required {
                    required.push(json!(a.name));
                }
            }
            json!({
                "name": c.name.replace(' ', "_"),
                "description": c.summary,
                "inputSchema": {"type": "object", "properties": props, "required": required},
            })
        })
        .collect()
}

/// Invoke a registry command against a vault opened at `root`.
/// `args`: JSON object keyed by ArgSpec names.
pub fn invoke_path(root: &Path, name: &str, args: &Value) -> Result<Value> {
    let engine = Engine::open(root)?;
    invoke(&engine, name, args)
}

fn get_str<'a>(args: &'a Value, k: &str) -> Option<&'a str> {
    args.get(k).and_then(|v| v.as_str())
}
fn get_bool(args: &Value, k: &str) -> bool {
    args.get(k).and_then(|v| v.as_bool()).unwrap_or(false)
}
fn get_usize(args: &Value, k: &str, d: usize) -> usize {
    args.get(k).and_then(|v| v.as_u64()).map(|x| x as usize).unwrap_or(d)
}

fn text_arg(args: &Value) -> Result<Option<String>> {
    // "text"/"content" option or explicit stdin content passed by the CLI.
    if let Some(t) = get_str(args, "text") {
        return Ok(Some(t.to_string()));
    }
    if let Some(t) = get_str(args, "content") {
        return Ok(Some(t.to_string()));
    }
    if let Some(t) = args.get("stdin").and_then(|v| v.as_str()) {
        return Ok(Some(t.to_string()));
    }
    Ok(None)
}

pub fn invoke(engine: &Engine, name: &str, args: &Value) -> Result<Value> {
    match name {
        "ping" => Ok(json!({"pong": true})),
        "cat" => {
            let note = req(args, "note")?;
            let path = engine.resolve_note(note)?;
            let content = engine.cat(note)?;
            Ok(json!({"path": path, "content": content}))
        }
        "new" => {
            let name = req(args, "name")?;
            let content = text_arg(args)?;
            let path = engine.new_note(name, content.as_deref(), get_str(args, "template"))?;
            Ok(json!({"path": path}))
        }
        "append" | "prepend" => {
            let note = req(args, "note")?;
            let text = text_arg(args)?.ok_or_else(|| {
                StoneError::InvalidInput("missing text (pass --text or pipe stdin)".into())
            })?;
            let path = if name == "append" {
                engine.append(note, &text)?
            } else {
                engine.prepend(note, &text)?
            };
            Ok(json!({"path": path}))
        }
        "edit" => {
            let note = req(args, "note")?;
            let find = req(args, "find")?;
            let replace = req(args, "replace")?;
            let r = engine.edit(note, find, replace, get_bool(args, "all"))?;
            Ok(json!(r))
        }
        "mv" => {
            let from = req(args, "from")?;
            let to = req(args, "to")?;
            let r = engine.mv(from, to, get_bool(args, "dry_run"))?;
            Ok(json!(r))
        }
        "rm" => {
            let note = req(args, "note")?;
            let path = engine.resolve_note(note)?;
            let trashed = engine.trash_file(&path)?;
            Ok(json!({"path": path, "trashed_to": trashed}))
        }
        "daily" => {
            let path = engine.daily(get_str(args, "date"), get_str(args, "append"))?;
            Ok(json!({"path": path}))
        }
        "search" => {
            let q: SearchQuery = crate::index::parse_search_query(req(args, "query")?);
            let hits = engine.index()?.search(&q, get_usize(args, "limit", 50))?;
            Ok(json!({"hits": hits}))
        }
        "links" => {
            let path = engine.resolve_note(req(args, "note")?)?;
            let rows = engine.index()?.links_from(&path)?;
            Ok(json!({"links": rows}))
        }
        "backlinks" => {
            let path = engine.resolve_note(req(args, "note")?)?;
            let rows = engine.index()?.backlinks(&path)?;
            Ok(json!({"backlinks": rows}))
        }
        "unresolved" => {
            let rows = engine.index()?.unresolved(get_str(args, "note"))?;
            Ok(json!({"unresolved": rows}))
        }
        "orphans" => {
            let rows = engine.index()?.orphans()?;
            Ok(json!({"orphans": rows}))
        }
        "tags" => {
            let tags = engine.index()?.all_tags()?;
            Ok(json!({"tags": tags.iter().map(|(t, c)| json!({"tag": t, "count": c})).collect::<Vec<_>>()}))
        }
        "tasks" => {
            let rows = engine.index()?.tasks(get_bool(args, "open"))?;
            Ok(json!({"tasks": rows}))
        }
        "props get" => {
            let note = req(args, "note")?;
            let key = req(args, "key")?;
            let path = engine.resolve_note(note)?;
            let text = engine.cat(&path)?;
            let v = crate::frontmatter::get_prop(&text, key);
            Ok(json!({"path": path, "key": key, "value": v}))
        }
        "props set" => {
            let note = req(args, "note")?;
            let key = req(args, "key")?;
            let value = req(args, "value")?;
            let path = engine.prop_set(note, key, value)?;
            Ok(json!({"path": path}))
        }
        "props query" => {
            let key = req(args, "key")?;
            let rows = engine.index()?.props_query(key, get_str(args, "value"))?;
            Ok(json!({"results": rows.iter().map(|(p, v)| json!({"path": p, "value": v})).collect::<Vec<_>>()}))
        }
        "graph" => {
            let edges = engine.index()?.edges()?;
            match get_str(args, "format").unwrap_or("json") {
                "dot" => {
                    let mut s = String::from("digraph vault {\n");
                    for (a, b) in &edges {
                        s.push_str(&format!("  {:?} -> {:?};\n", a, b));
                    }
                    s.push_str("}\n");
                    Ok(json!({"format": "dot", "graph": s}))
                }
                _ => Ok(json!({"format": "json", "edges": edges})),
            }
        }
        "reindex" => {
            let idx = crate::index::Index::open(&engine.local.index_db())?;
            let n = engine.refresh_index(&idx)?;
            Ok(json!({"indexed": n}))
        }
        "trash list" => {
            let items = engine.trash_list()?;
            Ok(json!({"trash": items}))
        }
        "trash restore" => {
            let name = req(args, "name")?;
            let dest = req(args, "dest")?;
            let path = engine.trash_restore(name, dest)?;
            Ok(json!({"path": path}))
        }
        "sync setup" => {
            let server = req(args, "server")?;
            let password = req(args, "password")?;
            let device = get_str(args, "device").map(str::to_string).unwrap_or_else(|| {
                std::env::var("COMPUTERNAME")
                    .or_else(|_| std::env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "device".into())
            });
            let out = SyncAgent::setup(&engine.root, server, &device, password)?;
            Ok(json!({
                "device_id": out.device_id,
                "vault_id": out.vault_id,
                "recovery_key": out.recovery_key,
                "note": "SAVE THE RECOVERY KEY — a lost password without it means lost data.",
            }))
        }
        "sync invite" => {
            let agent = SyncAgent::open(&engine.root)?;
            let device = get_str(args, "device").unwrap_or("device");
            let (device_id, token) = agent.invite(device)?;
            Ok(json!({
                "device_id": device_id,
                "token": token,
                "vault_id": agent.cfg.vault_id,
                "server": agent.cfg.server_url,
                "note": "give `token` + the vault password to the new device (stone sync join)",
            }))
        }
        "sync join" => {
            let server = req(args, "server")?;
            let vault_id = req(args, "vault_id")?;
            let token = req(args, "token")?;
            let password = req(args, "password")?;
            let device = get_str(args, "device").unwrap_or("device");
            SyncAgent::join(&engine.root, server, vault_id, token, device, password)?;
            Ok(json!({"vault_id": vault_id, "joined": true}))
        }
        "sync status" => {
            let st = sync::status(engine)?;
            Ok(json!(st))
        }
        "sync now" => {
            let agent = SyncAgent::open(&engine.root)?;
            let report = agent.sync_now(engine, get_bool(args, "force"))?;
            Ok(json!(report))
        }
        "sync conflicts" => {
            let agent = SyncAgent::open(&engine.root)?;
            let list = agent.conflicts(engine)?;
            Ok(json!({"conflicts": list}))
        }
        "sync history" => {
            let agent = SyncAgent::open(&engine.root)?;
            let rows = agent.history(engine, req(args, "note")?)?;
            Ok(json!({"versions": rows}))
        }
        "sync restore" => {
            let agent = SyncAgent::open(&engine.root)?;
            let path = agent.restore(engine, req(args, "note")?, req(args, "version")?)?;
            Ok(json!({"path": path}))
        }
        other => Err(StoneError::NotFound(format!("command {other}"))),
    }
}

fn req<'a>(args: &'a Value, k: &str) -> Result<&'a str> {
    get_str(args, k).ok_or_else(|| StoneError::InvalidInput(format!("missing argument {k}")))
}

/// Serialize a successful result envelope.
pub fn ok_envelope<T: Serialize>(v: T) -> Value {
    json!({"ok": true, "data": v})
}

pub fn err_envelope(e: &StoneError) -> Value {
    json!({"ok": false, "error": {"code": e.code(), "message": e.to_string()}})
}
