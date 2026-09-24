//! `stone mcp` — MCP server over stdio.
//!
//! Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP stdio).
//! Tools come straight from the stone-core command registry (the entries
//! marked `mcp: true` — deletes stay CLI-only by design).

use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use stone_core::error::StoneError;
use stone_core::{daemon, registry, Engine};

pub fn serve(root: &Path) -> Result<(), StoneError> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(StoneError::Io)?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                write_msg(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0", "id": Value::Null,
                        "error": {"code": -32700, "message": e.to_string()}
                    }),
                )?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let is_notification = req.get("id").is_none();
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        match method {
            "initialize" => {
                write_msg(
                    &mut out,
                    &json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "protocolVersion": params.get("protocolVersion")
                                .and_then(|v| v.as_str()).unwrap_or("2025-03-26"),
                            "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": {"name": "stone", "version": env!("CARGO_PKG_VERSION")},
                        }
                    }),
                )?;
            }
            "notifications/initialized" | "initialized" => {}
            "ping" => {
                write_msg(&mut out, &json!({"jsonrpc": "2.0", "id": id, "result": {}}))?;
            }
            "tools/list" => {
                let tools = registry::mcp_tools();
                write_msg(
                    &mut out,
                    &json!({"jsonrpc": "2.0", "id": id, "result": {"tools": tools}}),
                )?;
            }
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .replace('_', " ");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                match call_tool(root, &name, &args) {
                    Ok(data) => {
                        let text = match &data {
                            Value::String(s) => s.clone(),
                            other => serde_json::to_string_pretty(other).unwrap_or_default(),
                        };
                        write_msg(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0", "id": id,
                                "result": {"content": [{"type": "text", "text": text}], "isError": false}
                            }),
                        )?;
                    }
                    Err(e) => {
                        write_msg(
                            &mut out,
                            &json!({
                                "jsonrpc": "2.0", "id": id,
                                "result": {"content": [{"type": "text", "text": e.to_string()}], "isError": true}
                            }),
                        )?;
                    }
                }
            }
            _ => {
                if !is_notification {
                    write_msg(
                        &mut out,
                        &json!({
                            "jsonrpc": "2.0", "id": id,
                            "error": {"code": -32601, "message": format!("no method {method}")}
                        }),
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Forward to the daemon when it's up (shared lock, watcher-aware), else
/// run the registry command in-process.
fn call_tool(root: &Path, name: &str, args: &Value) -> Result<Value, StoneError> {
    if let Some(resp) = daemon::forward(
        root,
        &json!({"id": 1, "command": name, "args": args}),
        std::time::Duration::from_secs(120),
    ) {
        if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            return Ok(resp.get("data").cloned().unwrap_or(Value::Null));
        }
        if let Some(err) = resp.get("error") {
            return Err(StoneError::Message(
                err.get("message").and_then(|v| v.as_str()).unwrap_or("error").to_string(),
            ));
        }
    }
    let engine = Engine::open(root)?;
    registry::invoke(&engine, name, args)
}

fn write_msg(out: &mut impl Write, v: &Value) -> Result<(), StoneError> {
    let line = serde_json::to_string(v).map_err(StoneError::Json)?;
    out.write_all(line.as_bytes()).map_err(StoneError::Io)?;
    out.write_all(b"\n").map_err(StoneError::Io)?;
    out.flush().map_err(StoneError::Io)?;
    Ok(())
}
