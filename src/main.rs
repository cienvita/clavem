mod usage;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use async_stream::stream;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;
use clap::Parser;
use futures_util::StreamExt;
use tracing::{error, info};

use crate::usage::{Sniffer, Tokens, Totals};

const UPSTREAM: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Parser, Debug)]
#[command(version, about = "Claude proxy with token accounting")]
struct Args {
    /// Local port to listen on
    #[arg(short, long, default_value_t = 4567)]
    port: u16,

    /// Path to anthropic api key file (single line, key only)
    #[arg(short, long, default_value = "~/.config/clavem/anthropic.key")]
    key_file: PathBuf,
}

struct AppState {
    client: reqwest::Client,
    api_key: String,
    totals: Mutex<Totals>,
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

    let key_path = expand_tilde(&args.key_file);
    let api_key = read_key_file(&key_path)
        .with_context(|| format!("reading anthropic key from {}", key_path.display()))?;

    let state = Arc::new(AppState {
        client: reqwest::Client::new(),
        api_key,
        totals: Mutex::new(Totals::default()),
    });

    let app = Router::new()
        .route("/{*rest}", any(forward))
        .with_state(state.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], args.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("clavem listening on http://{addr} -> {UPSTREAM}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;

    state.totals.lock().unwrap().print();
    Ok(())
}

async fn forward(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match do_forward(state, req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("forward error: {e:#}");
            Response::builder()
                .status(502)
                .body(Body::from(format!("clavem upstream error: {e}\n")))
                .unwrap()
        }
    }
}

async fn do_forward(state: Arc<AppState>, req: Request) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();
    let query = parts.uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let url = format!("{UPSTREAM}{path}{query}");
    info!("{} {}", parts.method, path);

    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .context("reading request body")?;

    let mut builder = state.client.request(parts.method, &url);
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if matches!(
            n,
            "host"
                | "x-api-key"
                | "authorization"
                | "content-length"
                | "connection"
                | "transfer-encoding"
                | "accept-encoding"
        ) {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder = builder.header("x-api-key", &state.api_key);
    if !parts.headers.contains_key("anthropic-version") {
        builder = builder.header("anthropic-version", ANTHROPIC_VERSION);
    }
    let upstream = builder
        .body(body_bytes)
        .send()
        .await
        .context("sending upstream")?;

    let status = upstream.status();
    let mut resp = Response::builder().status(status);
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    for (name, value) in upstream.headers().iter() {
        let n = name.as_str();
        if matches!(n, "transfer-encoding" | "connection" | "content-length") {
            continue;
        }
        resp = resp.header(name, value);
    }

    let totals = state.clone();
    let body_stream = stream! {
        let mut up = upstream.bytes_stream();
        let mut sniff = Sniffer::new(&content_type);
        let track = status.is_success();
        while let Some(item) = up.next().await {
            if track && let Ok(b) = &item {
                sniff.feed(b);
            }
            yield item;
        }
        if track && let Some((model, t)) = sniff.finalize() {
            let grand = totals.totals.lock().unwrap().record(&model, &t);
            report_request(&model, &t, &grand);
        }
    };

    Ok(resp.body(Body::from_stream(body_stream))?)
}

fn report_request(model: &str, t: &Tokens, grand: &Tokens) {
    info!(
        "[{model}] in={} out={} cache_create={} cache_read={} | total in={} out={} cache_create={} cache_read={}",
        t.input, t.output, t.cache_create, t.cache_read,
        grand.input, grand.output, grand.cache_create, grand.cache_read
    );
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    info!("shutting down");
}

fn expand_tilde(p: &Path) -> PathBuf {
    let s = match p.to_str() {
        Some(s) => s,
        None => return p.to_path_buf(),
    };
    let rest = match s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) {
        Some(r) => r,
        None => return p.to_path_buf(),
    };
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home {
        Some(h) => h.join(rest),
        None => p.to_path_buf(),
    }
}

fn read_key_file(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    let key = text.trim();
    if key.is_empty() {
        bail!("key file is empty");
    }
    Ok(key.to_string())
}
