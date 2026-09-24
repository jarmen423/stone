//! `stone` — the headless CLI. Every subcommand maps onto one entry in the
//! stone-core command registry (the same table MCP tools and the GUI palette
//! come from). Execution mode: forward to the running per-vault daemon when
//! one is up, else run in-process — never needs a GUI.

mod mcp;

use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode as ProcExit;
use stone_core::config::{self, VaultRegistry};
use stone_core::error::StoneError;
use stone_core::{daemon, registry, Engine, ExitCode};

#[derive(Parser)]
#[command(name = "stone", version, about = "Stone: headless-first markdown notes")]
struct Cli {
    /// Vault path or registry name.
    #[arg(long, global = true)]
    vault: Option<String>,
    /// Machine-readable output: {"ok":true,"data":...} / {"ok":false,"error":{...}}
    #[arg(long, global = true)]
    json: bool,
    /// Show what a mutating command would do without doing it.
    #[arg(long, global = true)]
    dry_run: bool,
    /// Bypass the daemon even if one is running.
    #[arg(long, global = true)]
    no_daemon: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a vault at PATH (writes .stone/vault.toml, registers it).
    Init {
        path: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
    /// List registered vaults.
    Vaults,
    /// Print a note's contents.
    Cat { note: String },
    /// Create a note (content from --content or stdin).
    New {
        name: String,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        template: Option<String>,
    },
    /// Append text (arg or stdin) to a note.
    Append {
        note: String,
        text: Option<String>,
    },
    /// Prepend text (arg or stdin) to a note.
    Prepend {
        note: String,
        text: Option<String>,
    },
    /// Find/replace inside a note.
    Edit {
        note: String,
        #[arg(long)]
        find: String,
        #[arg(long)]
        replace: String,
        #[arg(long)]
        all: bool,
    },
    /// Move/rename a note, rewriting every backlink that resolves to it.
    Mv { from: String, to: String },
    /// Move a note to the vault trash (.stone/trash/).
    Rm { note: String },
    /// Open/create today's daily note; optionally append text.
    Daily {
        /// YYYY-MM-DD (default: today).
        #[arg(long)]
        date: Option<String>,
        #[arg(long)]
        append: Option<String>,
    },
    /// Search. `tag:#x`, `path:dir/`, `"phrase"`, `prop:key=value`, bare terms.
    Search {
        query: String,
        #[arg(long, default_value = "50")]
        limit: usize,
    },
    /// Outgoing links from a note.
    Links { note: String },
    /// Notes linking to a note.
    Backlinks { note: String },
    /// Links that resolve to nothing.
    Unresolved { note: Option<String> },
    /// Notes with no incoming links.
    Orphans,
    /// All tags with counts.
    Tags,
    /// Tasks; --open for unchecked only.
    Tasks {
        #[arg(long)]
        open: bool,
    },
    /// Frontmatter properties.
    Props {
        #[command(subcommand)]
        sub: PropsCmd,
    },
    /// Note link graph.
    Graph {
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Rebuild the index from disk.
    Reindex,
    /// Vault trash.
    Trash {
        #[command(subcommand)]
        sub: TrashCmd,
    },
    /// Encrypted sync.
    Sync {
        #[command(subcommand)]
        sub: SyncCmd,
    },
    /// Per-vault daemon (watch + index + sync + RPC for the CLI).
    Daemon {
        #[command(subcommand)]
        sub: DaemonCmd,
    },
    /// MCP server over stdio (JSON-RPC, newline-delimited).
    Mcp,
}

#[derive(Subcommand)]
enum PropsCmd {
    Get { note: String, key: String },
    Set { note: String, key: String, value: String },
    Query { key: String, value: Option<String> },
}

#[derive(Subcommand)]
enum TrashCmd {
    List,
    Restore { name: String, dest: String },
}

#[derive(Subcommand)]
enum SyncCmd {
    /// Set up encrypted sync for this vault on a stone-server.
    Setup {
        #[arg(long)]
        server: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        device: Option<String>,
    },
    /// Mint a device token to give to another machine.
    Invite {
        #[arg(long)]
        device: Option<String>,
    },
    /// Onboard this device with an invite token + vault password.
    Join {
        #[arg(long)]
        server: String,
        #[arg(long)]
        vault_id: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        password: String,
        #[arg(long)]
        device: Option<String>,
    },
    Status,
    /// Push local pending + pull remote changes now.
    Now {
        #[arg(long)]
        force: bool,
    },
    /// List conflict copies.
    Conflicts,
    /// Version history for a note.
    History { note: String },
    /// Restore a note to an older version.
    Restore { note: String, #[arg(long)] version: String },
}

#[derive(Subcommand)]
enum DaemonCmd {
    /// Run the daemon in the foreground.
    Run {
        #[arg(long, default_value = "5")]
        sync_every: u64,
    },
    /// Start the daemon in the background.
    Start {
        #[arg(long, default_value = "5")]
        sync_every: u64,
    },
    Stop,
    Status,
    /// Print/perform the OS service install for this vault.
    Install,
}

/// Read piped stdin (empty when stdin is a terminal).
fn piped_stdin() -> Option<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        return None;
    }
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).ok()?;
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() -> ProcExit {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match run(cli) {
        Ok(code) => ProcExit::from(code as u8),
        Err(e) => {
            // envelope for non-registry paths (init/vaults/daemon/mcp errors)
            eprintln!("{e}");
            ProcExit::from(ExitCode::Error as u8)
        }
    }
}

fn run(cli: Cli) -> Result<u8, StoneError> {
    match &cli.cmd {
        Cmd::Init { path, name } => {
            config::init_vault(path, name.as_deref())?;
            let canon = path.canonicalize().unwrap_or(path.clone());
            let mut reg = VaultRegistry::load();
            let reg_name = name
                .clone()
                .or_else(|| {
                    canon
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                })
                .unwrap_or_else(|| "vault".to_string());
            reg.vaults
                .insert(reg_name.clone(), canon.display().to_string());
            if reg.current.is_none() {
                reg.current = Some(reg_name);
            }
            reg.save()?;
            return emit(&cli, json!({"vault": canon.display().to_string()}), |v| {
                format!("initialized vault at {}", v["vault"].as_str().unwrap_or(""))
            });
        }
        Cmd::Vaults => {
            let reg = VaultRegistry::load();
            let list: Vec<Value> = reg
                .vaults
                .iter()
                .map(|(n, p)| {
                    json!({
                        "name": n,
                        "path": p,
                        "current": reg.current.as_deref() == Some(n.as_str()),
                    })
                })
                .collect();
            return emit(&cli, json!({"vaults": list}), |v| {
                let mut s = String::new();
                for x in v["vaults"].as_array().unwrap_or(&vec![]) {
                    let mark = if x["current"].as_bool().unwrap_or(false) { "*" } else { " " };
                    s.push_str(&format!(
                        "{mark} {}  {}\n",
                        x["name"].as_str().unwrap_or(""),
                        x["path"].as_str().unwrap_or("")
                    ));
                }
                s
            });
        }
        Cmd::Daemon { sub } => return daemon_cmd(&cli, sub),
        Cmd::Mcp => {
            let root = config::resolve_vault(cli.vault.as_deref())?;
            return mcp::serve(&root).map(|_| 0);
        }
        _ => {}
    }

    // everything below is a vault command: resolve vault → forward or direct
    let (name, args) = command_args(&cli);
    let root = config::resolve_vault(cli.vault.as_deref())?;
    let stdin_text = piped_stdin();
    let mut args = args;
    if let Some(t) = stdin_text {
        args.as_object_mut().map(|m| {
            if !m.contains_key("text") && !m.contains_key("content") {
                m.insert("stdin".into(), json!(t));
            }
        });
    }
    if cli.dry_run {
        args.as_object_mut().map(|m| m.insert("dry_run".into(), json!(true)));
    }

    let result = if !cli.no_daemon {
        daemon::forward(
            &root,
            &json!({"id": 1, "command": name, "args": args}),
            std::time::Duration::from_secs(120),
        )
        .and_then(|v| if v.get("ok").is_some() { Some(v) } else { None })
        .map(|v| {
            if v["ok"].as_bool() == Some(true) {
                Ok(v["data"].clone())
            } else {
                Err(v["error"].clone())
            }
        })
    } else {
        None
    };

    let data = match result {
        Some(Ok(d)) => Ok(d),
        Some(Err(errv)) => Err(StoneError::Message(
            errv["message"].as_str().unwrap_or("error").to_string(),
        )),
        None => {
            let engine = Engine::open(&root)?;
            registry::invoke(&engine, &name, &args)
        }
    };

    match data {
        Ok(v) => emit(&cli, v, |v| humanize(&name, v)),
        Err(e) => {
            if cli.json {
                println!("{}", serde_json::to_string(&registry::err_envelope(&e))?);
            } else {
                eprintln!("stone: {e}");
            }
            Ok(e.exit_code() as u8)
        }
    }
}

/// Map the parsed CLI command to (registry name, args json).
fn command_args(cli: &Cli) -> (String, Value) {
    let mut m = serde_json::Map::new();
    let name = match &cli.cmd {
        Cmd::Cat { note } => {
            m.insert("note".into(), json!(note));
            "cat"
        }
        Cmd::New { name, content, template } => {
            m.insert("name".into(), json!(name));
            if let Some(c) = content {
                m.insert("content".into(), json!(c));
            }
            if let Some(t) = template {
                m.insert("template".into(), json!(t));
            }
            "new"
        }
        Cmd::Append { note, text } => {
            m.insert("note".into(), json!(note));
            if let Some(t) = text {
                m.insert("text".into(), json!(t));
            }
            "append"
        }
        Cmd::Prepend { note, text } => {
            m.insert("note".into(), json!(note));
            if let Some(t) = text {
                m.insert("text".into(), json!(t));
            }
            "prepend"
        }
        Cmd::Edit { note, find, replace, all } => {
            m.insert("note".into(), json!(note));
            m.insert("find".into(), json!(find));
            m.insert("replace".into(), json!(replace));
            m.insert("all".into(), json!(all));
            "edit"
        }
        Cmd::Mv { from, to } => {
            m.insert("from".into(), json!(from));
            m.insert("to".into(), json!(to));
            "mv"
        }
        Cmd::Rm { note } => {
            m.insert("note".into(), json!(note));
            "rm"
        }
        Cmd::Daily { date, append } => {
            if let Some(d) = date {
                m.insert("date".into(), json!(d));
            }
            if let Some(a) = append {
                m.insert("append".into(), json!(a));
            }
            "daily"
        }
        Cmd::Search { query, limit } => {
            m.insert("query".into(), json!(query));
            m.insert("limit".into(), json!(limit));
            "search"
        }
        Cmd::Links { note } => {
            m.insert("note".into(), json!(note));
            "links"
        }
        Cmd::Backlinks { note } => {
            m.insert("note".into(), json!(note));
            "backlinks"
        }
        Cmd::Unresolved { note } => {
            if let Some(n) = note {
                m.insert("note".into(), json!(n));
            }
            "unresolved"
        }
        Cmd::Orphans => "orphans",
        Cmd::Tags => "tags",
        Cmd::Tasks { open } => {
            m.insert("open".into(), json!(open));
            "tasks"
        }
        Cmd::Props { sub } => match sub {
            PropsCmd::Get { note, key } => {
                m.insert("note".into(), json!(note));
                m.insert("key".into(), json!(key));
                "props get"
            }
            PropsCmd::Set { note, key, value } => {
                m.insert("note".into(), json!(note));
                m.insert("key".into(), json!(key));
                m.insert("value".into(), json!(value));
                "props set"
            }
            PropsCmd::Query { key, value } => {
                m.insert("key".into(), json!(key));
                if let Some(v) = value {
                    m.insert("value".into(), json!(v));
                }
                "props query"
            }
        },
        Cmd::Graph { format } => {
            m.insert("format".into(), json!(format));
            "graph"
        }
        Cmd::Reindex => "reindex",
        Cmd::Trash { sub } => match sub {
            TrashCmd::List => "trash list",
            TrashCmd::Restore { name, dest } => {
                m.insert("name".into(), json!(name));
                m.insert("dest".into(), json!(dest));
                "trash restore"
            }
        },
        Cmd::Sync { sub } => match sub {
            SyncCmd::Setup { server, password, device } => {
                m.insert("server".into(), json!(server));
                m.insert("password".into(), json!(password));
                if let Some(d) = device {
                    m.insert("device".into(), json!(d));
                }
                "sync setup"
            }
            SyncCmd::Invite { device } => {
                if let Some(d) = device {
                    m.insert("device".into(), json!(d));
                }
                "sync invite"
            }
            SyncCmd::Join { server, vault_id, token, password, device } => {
                m.insert("server".into(), json!(server));
                m.insert("vault_id".into(), json!(vault_id));
                m.insert("token".into(), json!(token));
                m.insert("password".into(), json!(password));
                if let Some(d) = device {
                    m.insert("device".into(), json!(d));
                }
                "sync join"
            }
            SyncCmd::Status => "sync status",
            SyncCmd::Now { force } => {
                m.insert("force".into(), json!(force));
                "sync now"
            }
            SyncCmd::Conflicts => "sync conflicts",
            SyncCmd::History { note } => {
                m.insert("note".into(), json!(note));
                "sync history"
            }
            SyncCmd::Restore { note, version } => {
                m.insert("note".into(), json!(note));
                m.insert("version".into(), json!(version));
                "sync restore"
            }
        },
        _ => unreachable!("handled earlier"),
    };
    (name.to_string(), Value::Object(m))
}

fn emit(cli: &Cli, data: Value, human: impl Fn(&Value) -> String) -> Result<u8, StoneError> {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string(&registry::ok_envelope(&data)).map_err(StoneError::Json)?
        );
    } else {
        let s = human(&data);
        if !s.is_empty() {
            println!("{s}");
        }
    }
    Ok(0)
}

/// Human rendering per command (fallback: pretty JSON).
fn humanize(name: &str, v: &Value) -> String {
    match name {
        "cat" => v["content"].as_str().unwrap_or("").to_string(),
        "new" | "append" | "prepend" | "edit" | "mv" | "rm" | "daily" | "props set"
        | "trash restore" | "sync restore" => v["path"]
            .as_str()
            .map(|p| p.to_string())
            .unwrap_or_else(|| serde_json::to_string_pretty(v).unwrap_or_default()),
        "search" => v["hits"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|h| {
                        format!(
                            "{}:{}  {}",
                            h["path"].as_str().unwrap_or(""),
                            h["line"].as_u64().unwrap_or(0),
                            h["snippet"].as_str().unwrap_or("")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "links" => v["links"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        let target = x["resolved"].as_str().unwrap_or("?");
                        format!("{}:{} -> {}", x["line"].as_u64().unwrap_or(0), x["target"].as_str().unwrap_or(""), target)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "backlinks" => v["backlinks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| format!("{}:{}", x["src"].as_str().unwrap_or(""), x["line"].as_u64().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "unresolved" => v["unresolved"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| format!("{}:{}", x["path"].as_str().unwrap_or(""), x["target"].as_str().unwrap_or("")))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "orphans" => v["orphans"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| x.as_str().unwrap_or("").to_string())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "tags" => v["tags"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| format!("{} ({})", x["tag"].as_str().unwrap_or(""), x["count"].as_u64().unwrap_or(0)))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "tasks" => v["tasks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|x| {
                        let cb = if x["done"].as_bool().unwrap_or(false) { "[x]" } else { "[ ]" };
                        format!("{}:{} {} {}", x["path"].as_str().unwrap_or(""), x["line"].as_u64().unwrap_or(0), cb, x["text"].as_str().unwrap_or(""))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        "graph" if v["format"].as_str() == Some("dot") => {
            v["graph"].as_str().unwrap_or("").to_string()
        }
        "sync setup" => format!(
            "sync configured (vault {})\nSAVE THIS RECOVERY KEY — a lost password without it means lost data:\n  {}",
            v["vault_id"].as_str().unwrap_or(""),
            v["recovery_key"].as_str().unwrap_or("")
        ),
        _ => serde_json::to_string_pretty(v).unwrap_or_default(),
    }
}

fn daemon_cmd(cli: &Cli, sub: &DaemonCmd) -> Result<u8, StoneError> {
    match sub {
        DaemonCmd::Run { sync_every } => {
            let sync_every = *sync_every;
            let root = config::resolve_vault(cli.vault.as_deref())?;
            use std::sync::atomic::AtomicBool;
            use std::sync::Arc;
            let shutdown = Arc::new(AtomicBool::new(false));
            daemon::run(&root, sync_every, shutdown)?;
            Ok(0)
        }
        DaemonCmd::Start { sync_every } => {
            let sync_every = *sync_every;
            let root = config::resolve_vault(cli.vault.as_deref())?;
            if daemon::daemon_info(&root).is_some() {
                return emit(&cli, json!({"running": true}), |_| "daemon already running".into());
            }
            let exe = std::env::current_exe()?;
            let mut c = std::process::Command::new(exe);
            c.arg("daemon")
                .arg("run")
                .arg("--sync-every")
                .arg(sync_every.to_string())
                .arg("--vault")
                .arg(&root)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                c.creation_flags(0x00000200 | 0x00000008); // CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS
            }
            c.spawn()?;
            // wait for the port file to appear
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let mut up = false;
            while std::time::Instant::now() < deadline {
                if daemon::daemon_info(&root).is_some() {
                    up = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            emit(&cli, json!({"running": up}), |v| {
                if v["running"].as_bool() == Some(true) {
                    "daemon started".into()
                } else {
                    "daemon spawned but did not come up within 5s".into()
                }
            })
        }
        DaemonCmd::Stop => {
            let root = config::resolve_vault(cli.vault.as_deref())?;
            let stopped = daemon::stop(&root);
            emit(&cli, json!({"stopped": stopped}), |v| {
                if v["stopped"].as_bool() == Some(true) {
                    "daemon stopped".into()
                } else {
                    "no daemon running".into()
                }
            })
        }
        DaemonCmd::Status => {
            let root = config::resolve_vault(cli.vault.as_deref())?;
            match daemon::daemon_info(&root) {
                Some(info) => emit(&cli, serde_json::to_value(&info).map_err(StoneError::Json)?, |v| {
                    format!(
                        "running on 127.0.0.1:{} (pid {})",
                        v["port"].as_u64().unwrap_or(0),
                        v["pid"].as_u64().unwrap_or(0)
                    )
                }),
                None => emit(&cli, json!({"running": false}), |_| "not running".into()),
            }
        }
        DaemonCmd::Install => {
            let root = config::resolve_vault(cli.vault.as_deref())?;
            let msg = daemon::install_service(&root)?;
            emit(&cli, json!({"result": msg}), |v| {
                v["result"].as_str().unwrap_or("").to_string()
            })
        }
    }
}
