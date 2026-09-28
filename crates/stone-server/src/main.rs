//! `stone-server` binary — thin wrapper over the library `serve`.

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "stone-server", about = "Stone encrypted sync server")]
struct Cli {
    /// Data directory (blobs + sqlite).
    #[arg(long, default_value = "stone-data")]
    data: PathBuf,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:8484")]
    bind: String,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stone_server=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let listener = tokio::net::TcpListener::bind(&cli.bind).await?;
    tracing::info!("stone-server on {}", cli.bind);
    stone_server::serve(listener, cli.data).await
}
