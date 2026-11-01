use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};

use clavem::admin::{self, AdminState};
use clavem::auth::Auth;
use clavem::config::{Config, expand_tilde};
use clavem::db::Db;
use clavem::keys::{Pepper, TokenKey};
use clavem::pricing::PriceBook;
use clavem::provider::Registry;
use clavem::proxy::{AppState, Backend, app};
use clavem::writer::Writer;

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

const PRICE_RELOAD: Duration = Duration::from_secs(60);
const WRITER_DRAIN: Duration = Duration::from_secs(10);

fn read_secret(path: &Path, what: &str) -> Result<Vec<u8>> {
    let raw =
        std::fs::read(path).with_context(|| format!("reading {what} from {}", path.display()))?;
    let trimmed = raw.trim_ascii().to_vec();
    if trimmed.is_empty() {
        anyhow::bail!("{what} file {} is empty", path.display());
    }
    Ok(trimmed)
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

    let mut writer_handle = None;
    let state = match (&config.database, &config.auth) {
        (Some(dbc), Some(ac)) => {
            let pepper = Pepper::new(read_secret(&ac.pepper_file, "auth.pepper_file")?)?;
            let token_key = TokenKey::new(read_secret(&ac.token_key_file, "auth.token_key_file")?)?;
            let db = Db::connect(dbc).await?;
            let auth = Arc::new(Auth::new(
                db.clone(),
                pepper,
                token_key,
                Duration::from_secs(ac.token_max_ttl_secs),
                Duration::from_secs(ac.cache_ttl_secs),
            ));
            let prices = db.load_prices().await.context("loading prices")?;
            info!("loaded {} prices", prices.len());
            let (writer, handle) = Writer::spawn(db);
            writer_handle = Some(handle);
            Arc::new(AppState::with_backend(
                registry,
                Backend {
                    auth,
                    prices: RwLock::new(PriceBook::new(prices)),
                    writer,
                },
            ))
        }
        _ => {
            warn!(
                "no [database] configured: clients are not authenticated and usage is kept in \
                 memory only. Do not expose {addr} beyond this host."
            );
            Arc::new(AppState::new(registry))
        }
    };

    if state.backend.is_some() {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PRICE_RELOAD);
            tick.tick().await;
            loop {
                tick.tick().await;
                if let Err(e) = admin::reload_prices(&st).await {
                    error!("reloading prices: {e:#}");
                }
                let be = st.backend.as_ref().expect("checked above");
                // Counters for periods that ended more than a month ago.
                be.auth
                    .spend
                    .prune_before(chrono::Utc::now().date_naive() - chrono::Days::new(40));
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("clavem listening on http://{addr}");
    for p in state.registry.providers() {
        info!(
            "  /{}/ -> {} ({:?}, credentials: {})",
            p.name,
            p.base_url,
            p.kind,
            p.credential_names().collect::<Vec<_>>().join(", ")
        );
    }

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);

    let admin_task = match &config.admin {
        Some(ac) => {
            let token = String::from_utf8(read_secret(&ac.token_file, "admin.token_file")?)
                .context("admin token must be UTF-8")?;
            anyhow::ensure!(
                token.len() >= 32,
                "admin token must be at least 32 characters"
            );
            let router = admin::router(Arc::new(AdminState {
                app: state.clone(),
                token,
            }));
            let l = tokio::net::TcpListener::bind(ac.listen).await?;
            info!("clavem admin API on http://{}", ac.listen);
            let mut rx = stop_rx.clone();
            Some(tokio::spawn(async move {
                axum::serve(l, router)
                    .with_graceful_shutdown(async move {
                        let _ = rx.changed().await;
                    })
                    .await
            }))
        }
        None => None,
    };

    axum::serve(listener, app(state.clone()))
        .with_graceful_shutdown(async move {
            shutdown().await;
            let _ = stop_tx.send(true);
        })
        .await?;

    if let Some(t) = admin_task
        && let Err(e) = t.await?
    {
        error!("admin API: {e:#}");
    }
    if let (Some(be), Some(h)) = (&state.backend, writer_handle) {
        be.writer.stop();
        if tokio::time::timeout(WRITER_DRAIN, h).await.is_err() {
            error!("usage writer did not drain within {WRITER_DRAIN:?}; unwritten events are lost");
        }
    }

    state.totals.lock().unwrap().print();
    Ok(())
}

/// Ctrl-C, or SIGTERM from systemd, docker or arig. Either drains the
/// usage writer before exit.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                warn!("cannot listen for SIGTERM, only Ctrl-C will drain on exit: {e}");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
    info!("shutting down");
}
