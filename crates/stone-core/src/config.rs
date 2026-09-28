//! Vault discovery and configuration.
//!
//! - Vault marker: `.stone/vault.toml` inside the vault root (synced).
//! - Device-local settings + cache: the OS cache dir (never synced).
//! - User-level vault registry: `<config dir>/stone/vaults.toml`.

use crate::error::{Result, StoneError};
use crate::paths::{normalize_rel, ExcludeSet};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const STONE_DIR: &str = ".stone";
pub const VAULT_TOML: &str = ".stone/vault.toml";
pub const SYNC_TOML: &str = ".stone/sync.toml";
pub const TRASH_DIR: &str = ".stone/trash";

/// Synced, in-vault settings (`.stone/vault.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VaultConfig {
    /// Display name; also the registry name when created via `vault init --name`.
    pub name: Option<String>,
    /// Daily notes folder (falls back to `.obsidian` daily-notes settings).
    pub daily_folder: Option<String>,
    /// Daily note filename strftime-ish format, e.g. `%Y-%m-%d`.
    pub daily_format: Option<String>,
    /// Folder for new notes created without a path.
    pub new_notes_folder: Option<String>,
    /// Folder containing template notes for `stone new --template`.
    pub templates_folder: Option<String>,
    /// Extra sync exclude globs (mirrored into ExcludeSet at open time).
    pub sync_excludes: Vec<String>,
}

/// `.stone/sync.toml` — extra excludes only (device-invariant, synced).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SyncToml {
    pub exclude: Vec<String>,
}

/// Sync connection state stored device-locally (NOT synced):
/// `<cache>/vaults/<hash>/sync.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SyncConfig {
    pub server_url: Option<String>,
    /// Opaque vault id on the server (keyed hash — server cannot guess names).
    pub vault_id: Option<String>,
    /// This device's token (bearer).
    pub device_token: Option<String>,
    /// Server-assigned device id — commits must carry this id.
    pub device_id: Option<String>,
    /// Device display name used in conflict copy names.
    pub device_name: Option<String>,
    /// base64url(vault key) — kept device-local; see `crypto` for wrapping.
    pub vault_key_b64: Option<String>,
    /// base64url(wrapped vault key) + Argon2 salt params for password changes.
    pub wrapped_key_b64: Option<String>,
    pub argon2_salt_b64: Option<String>,
}

/// Per-vault device-local paths inside the cache dir.
#[derive(Debug, Clone)]
pub struct VaultLocal {
    /// `<cache>/vaults/<id>/`
    pub dir: PathBuf,
}

impl VaultLocal {
    pub fn journal_db(&self) -> PathBuf {
        self.dir.join("journal.db")
    }
    pub fn index_db(&self) -> PathBuf {
        self.dir.join("index.db")
    }
    pub fn sync_lock(&self) -> PathBuf {
        self.dir.join("sync.lock")
    }
    pub fn daemon_port(&self) -> PathBuf {
        self.dir.join("daemon.port")
    }
    pub fn sync_toml(&self) -> PathBuf {
        self.dir.join("sync.toml")
    }
    pub fn ui_state(&self) -> PathBuf {
        self.dir.join("ui.toml")
    }
}

/// User-level registry of named vaults (`vaults.toml`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VaultRegistry {
    pub current: Option<String>,
    #[serde(default)]
    pub vaults: BTreeMap<String, String>, // name -> absolute path
}

impl VaultRegistry {
    pub fn load() -> Self {
        let p = registry_path();
        match fs::read_to_string(&p) {
            Ok(s) => toml::from_str(&s).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let p = registry_path();
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(StoneError::TomlSer)?;
        fs::write(&p, s)?;
        Ok(())
    }
}

/// Root config dir for the user (e.g. `%APPDATA%\stone` / `~/.config/stone`).
pub fn user_config_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "stone", "stone")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".stone-user"))
}

/// Root cache dir (e.g. `%LOCALAPPDATA%\stone\cache` / `~/.cache/stone`).
pub fn user_cache_dir() -> PathBuf {
    directories::ProjectDirs::from("dev", "stone", "stone")
        .map(|d| d.cache_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(".stone-cache"))
}

fn registry_path() -> PathBuf {
    user_config_dir().join("vaults.toml")
}

/// Stable filesystem-safe id for a vault root (keyed by absolute path).
pub fn vault_cache_id(vault_root: &Path) -> String {
    let canon = vault_root
        .canonicalize()
        .unwrap_or_else(|_| vault_root.to_path_buf());
    let h = blake3::hash(canon.to_string_lossy().as_bytes());
    hex::encode(&h.as_bytes()[..12])
}

/// Device-local dir for a vault.
pub fn vault_local_dir(vault_root: &Path) -> PathBuf {
    user_cache_dir()
        .join("vaults")
        .join(vault_cache_id(vault_root))
}

/// Walk up from `start` looking for a `.stone/` vault marker.
pub fn find_vault_up(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start.to_path_buf());
    while let Some(p) = cur {
        if p.join(STONE_DIR).join("vault.toml").is_file() {
            return Some(p);
        }
        cur = p.parent().map(|x| x.to_path_buf());
    }
    None
}

/// Resolve which vault to use, in priority order:
/// explicit --vault path > STONE_VAULT env > nearest vault above cwd > registry `current`.
pub fn resolve_vault(cli_vault: Option<&str>) -> Result<PathBuf> {
    if let Some(v) = cli_vault {
        return canonical_vault(Path::new(v));
    }
    if let Ok(v) = std::env::var("STONE_VAULT") {
        if !v.is_empty() {
            // env may be a name or a path
            if Path::new(&v).join(STONE_DIR).join("vault.toml").is_file() {
                return canonical_vault(Path::new(&v));
            }
            let reg = VaultRegistry::load();
            if let Some(p) = reg.vaults.get(&v) {
                return canonical_vault(Path::new(p));
            }
            return canonical_vault(Path::new(&v));
        }
    }
    let cwd = std::env::current_dir()?;
    if let Some(v) = find_vault_up(&cwd) {
        return Ok(v);
    }
    let reg = VaultRegistry::load();
    if let Some(name) = reg.current.clone() {
        if let Some(p) = reg.vaults.get(&name) {
            return canonical_vault(Path::new(p));
        }
    }
    Err(StoneError::NoVault)
}

fn canonical_vault(p: &Path) -> Result<PathBuf> {
    if !p.join(STONE_DIR).join("vault.toml").is_file() {
        return Err(StoneError::VaultNotFound(format!(
            "{} (no .stone/vault.toml)",
            p.display()
        )));
    }
    Ok(p.canonicalize().unwrap_or_else(|_| p.to_path_buf()))
}

/// Load `.stone/vault.toml` (missing → defaults).
pub fn load_vault_config(vault_root: &Path) -> VaultConfig {
    fs::read_to_string(vault_root.join(VAULT_TOML))
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Load `.stone/sync.toml` (missing → empty).
pub fn load_sync_toml(vault_root: &Path) -> SyncToml {
    fs::read_to_string(vault_root.join(SYNC_TOML))
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

/// Load device-local sync config for this vault.
pub fn load_sync_config(vault_root: &Path) -> SyncConfig {
    let p = vault_local_dir(vault_root).join("sync.toml");
    fs::read_to_string(&p)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_sync_config(vault_root: &Path, cfg: &SyncConfig) -> Result<()> {
    let p = vault_local_dir(vault_root).join("sync.toml");
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(cfg).map_err(StoneError::TomlSer)?;
    fs::write(&p, s)?;
    Ok(())
}

/// Effective exclude set: defaults + `.stone/sync.toml` + `vault.toml` extras.
pub fn effective_excludes(vault_root: &Path) -> ExcludeSet {
    let mut extra = load_sync_toml(vault_root).exclude;
    extra.extend(load_vault_config(vault_root).sync_excludes);
    ExcludeSet::default().with_extra(extra)
}

/// Initialize a vault at `path` (creates `.stone/vault.toml`, `.stone/` dirs).
pub fn init_vault(path: &Path, name: Option<&str>) -> Result<()> {
    let stone = path.join(STONE_DIR);
    fs::create_dir_all(stone.join("trash"))?;
    let cfg = VaultConfig {
        name: name.map(|s| s.to_string()),
        ..Default::default()
    };
    let s = toml::to_string_pretty(&cfg).map_err(StoneError::TomlSer)?;
    fs::write(stone.join("vault.toml"), s)?;
    Ok(())
}

/// Read matching Obsidian settings as defaults (read-only — we never write `.obsidian`).
/// Looks at `.obsidian/daily-notes.json` and `.obsidian/app.json`.
pub fn obsidian_defaults(vault_root: &Path) -> VaultConfig {
    let mut out = VaultConfig::default();
    let daily = vault_root.join(".obsidian/daily-notes.json");
    if let Ok(s) = fs::read_to_string(&daily) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            out.daily_folder = v
                .get("folder")
                .and_then(|x| x.as_str())
                .map(normalize_rel)
                .filter(|s| !s.is_empty());
            out.daily_format = v
                .get("format")
                .and_then(|x| x.as_str())
                .map(|f| obsidian_moment_to_strftime(f));
        }
    }
    let app = vault_root.join(".obsidian/app.json");
    if let Ok(s) = fs::read_to_string(&app) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(loc) = v.get("newFileLocation").and_then(|x| x.as_str()) {
                if loc == "folder" {
                    out.new_notes_folder = v
                        .get("newFileFolderPath")
                        .and_then(|x| x.as_str())
                        .map(normalize_rel)
                        .filter(|s| !s.is_empty());
                }
            }
        }
    }
    let templates = vault_root.join(".obsidian/templates.json");
    if let Ok(s) = fs::read_to_string(&templates) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            out.templates_folder = v
                .get("folder")
                .and_then(|x| x.as_str())
                .map(normalize_rel)
                .filter(|s| !s.is_empty());
        }
    }
    out
}

/// Convert Obsidian's Moment.js-ish daily format to chrono strftime.
/// Covers the common tokens (YYYY, YY, MM, DD, MMM, MMMM, dddd, DDDo is kept literal-ish).
pub fn obsidian_moment_to_strftime(fmt: &str) -> String {
    let mut s = fmt.to_string();
    // longest-first replacements
    for (from, to) in [
        ("YYYY", "%Y"),
        ("YY", "%y"),
        ("MMMM", "%B"),
        ("MMM", "%b"),
        ("MM", "%m"),
        ("DD", "%d"),
        ("D", "%d"),
        ("dddd", "%A"),
        ("ddd", "%a"),
    ] {
        s = s.replace(from, to);
    }
    s
}

/// Resolved daily-note settings (vault config → obsidian → defaults).
pub fn daily_settings(vault_root: &Path, cfg: &VaultConfig) -> (String, String) {
    let obs = obsidian_defaults(vault_root);
    let folder = cfg
        .daily_folder
        .clone()
        .or(obs.daily_folder)
        .unwrap_or_default();
    let format = cfg
        .daily_format
        .clone()
        .or(obs.daily_format)
        .unwrap_or_else(|| "%Y-%m-%d".to_string());
    (folder, format)
}
