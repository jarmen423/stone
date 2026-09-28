//! Error types shared across Stone.

use thiserror::Error;

/// CLI-facing exit codes (see spec: 0 success, 1 error, 2 not found, 3 conflict).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success = 0,
    Error = 1,
    NotFound = 2,
    Conflict = 3,
}

#[derive(Debug, Error)]
pub enum StoneError {
    #[error("{0}")]
    Message(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("vault not found: {0}")]
    VaultNotFound(String),

    #[error("no vault selected (use --vault, STONE_VAULT, or run inside a vault)")]
    NoVault,

    #[error("sync is not configured for this vault (run `stone sync setup`)")]
    SyncNotConfigured,

    #[error("ambiguous link `{0}` resolves to multiple notes: {1}")]
    AmbiguousLink(String, String),

    #[error("sync rejected: base versions are stale; pull, merge and retry ({0})")]
    SyncRejected(String),

    #[error("mass delete guard tripped: sync would delete {0} files ({1:.0}% of vault)")]
    MassDeleteGuard(usize, f64),

    #[error("a sync agent is already running for this vault")]
    SyncLockHeld,

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl StoneError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            StoneError::NotFound(_) | StoneError::VaultNotFound(_) => ExitCode::NotFound,
            StoneError::Conflict(_)
            | StoneError::SyncRejected(_)
            | StoneError::AmbiguousLink(..) => ExitCode::Conflict,
            _ => ExitCode::Error,
        }
    }

    /// Machine-readable error code used in `--json` output.
    pub fn code(&self) -> &'static str {
        match self {
            StoneError::Message(_) => "error",
            StoneError::NotFound(_) => "not_found",
            StoneError::Conflict(_) => "conflict",
            StoneError::InvalidInput(_) => "invalid_input",
            StoneError::VaultNotFound(_) => "vault_not_found",
            StoneError::NoVault => "no_vault",
            StoneError::SyncNotConfigured => "sync_not_configured",
            StoneError::AmbiguousLink(..) => "ambiguous_link",
            StoneError::SyncRejected(_) => "sync_rejected",
            StoneError::MassDeleteGuard(..) => "mass_delete_guard",
            StoneError::SyncLockHeld => "sync_lock_held",
            StoneError::Io(_) => "io",
            StoneError::Sqlite(_) => "sqlite",
            StoneError::Json(_) => "json",
            StoneError::TomlSer(_) => "toml",
            StoneError::Yaml(_) => "yaml",
            StoneError::Http(_) => "http",
            StoneError::Crypto(_) => "crypto",
        }
    }
}

pub type Result<T> = std::result::Result<T, StoneError>;

pub fn msg<S: Into<String>>(s: S) -> StoneError {
    StoneError::Message(s.into())
}
