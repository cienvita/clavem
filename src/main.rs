use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing::info;

use clavem::config::{Config, expand_tilde};
use clavem::provider::Registry;
use clavem::proxy::{AppState, app};

#[derive(Parser, Debug)]
#[command(version, about = "AI API gateway with token accounting")]
struct Args {
    /// Path to the config file
    #[arg(short, long, default_value = "~/.config/clavem/clavem.toml")]
    config: PathBuf,

    /// Override the listen port from the config
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "clavem=info".into()),
        )
        .init();

    let config = Config::load(&expand_tilde(&args.config))?;
    let registry = Registry::from_config(&config)?;

    let mut addr = config.server.listen;
    if let Some(port) = args.port {
        addr.set_port(port);
    }

    let state = Arc::new(AppState::new(registry));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("clavem listening on http://{addr}");
    for p in state.registry.providers() {
        info!("  /{}/ -> {} ({:?})", p.name, p.base_url, p.kind);
    }

    axum::serve(listener, app(state.clone()))
        .with_graceful_shutdown(shutdown())
        .await?;

    state.totals.lock().unwrap().print();
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutting down");
}
