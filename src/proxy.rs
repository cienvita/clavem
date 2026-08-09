use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_stream::stream;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::any;
use futures_util::StreamExt;
use http::StatusCode;
use tracing::{error, info};

use crate::provider::{Kind, Provider, Registry, strip_response_headers};
use crate::usage::{Sniffer, Tokens, Totals};

/// Cap on a buffered client request body. Bodies are read whole because
/// adapters need to inspect and (for some kinds) rewrite them.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

pub struct AppState {
    pub client: reqwest::Client,
    pub registry: Registry,
    pub totals: Mutex<Totals>,
}

impl AppState {
    pub fn new(registry: Registry) -> AppState {
        AppState {
            client: reqwest::Client::new(),
            registry,
            totals: Mutex::new(Totals::default()),
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    // Everything not claimed by a gateway-owned route is a pass-through.
    Router::new().fallback(any(forward)).with_state(state)
}

async fn forward(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match do_forward(state, req).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("forward error: {e:#}");
            error_response(StatusCode::BAD_GATEWAY, "upstream_error", &format!("{e:#}"))
        }
    }
}

async fn do_forward(state: Arc<AppState>, req: Request) -> Result<Response> {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path();

    let Some((provider, rest)) = state.registry.route(path) else {
        info!("{} {path} -> no provider", parts.method);
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown_provider",
            &format!(
                "no provider matches {path}; configured: {}",
                state
                    .registry
                    .providers()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    };

    let url = provider.upstream_url(&rest, parts.uri.query());
    info!("{} {path} -> {url}", parts.method);

    let body_bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(e) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "invalid_request",
                &format!("reading request body: {e}"),
            ));
        }
    };

    let upstream = state
        .client
        .request(parts.method, &url)
        .headers(provider.upstream_headers(&parts.headers))
        .body(body_bytes)
        .send()
        .await
        .context("sending upstream")?;

    let status = upstream.status();
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let mut resp = Response::builder().status(status);
    if let Some(headers) = resp.headers_mut() {
        headers.extend(upstream.headers().clone());
        strip_response_headers(headers);
    }

    let mut sniff = sniffer_for(&provider, status, &content_type);
    let state = state.clone();
    let provider_name = provider.name.clone();
    let body_stream = stream! {
        let mut up = upstream.bytes_stream();
        while let Some(item) = up.next().await {
            if let (Some(s), Ok(b)) = (sniff.as_mut(), &item) {
                s.feed(b);
            }
            yield item;
        }
        // A client that disconnects mid-stream ends the loop early; we
        // still record whatever the sniffer saw.
        if let Some((model, t)) = sniff.and_then(Sniffer::finalize) {
            let grand = state.totals.lock().unwrap().record(&provider_name, &model, &t);
            report_request(&provider_name, &model, &t, &grand);
        }
    };

    Ok(resp.body(Body::from_stream(body_stream))?)
}

/// Only successful responses are metered, and only for kinds that have a
/// sniffer. OpenAI-shaped and per-request metering land with phase 2.
fn sniffer_for(provider: &Provider, status: StatusCode, content_type: &str) -> Option<Sniffer> {
    if !status.is_success() {
        return None;
    }
    match provider.kind {
        Kind::Anthropic => Some(Sniffer::new(content_type)),
        Kind::Xai | Kind::Azure => None,
    }
}

fn report_request(provider: &str, model: &str, t: &Tokens, grand: &Tokens) {
    info!(
        "[{provider}/{model}] in={} out={} cache_create={} cache_read={} | total in={} out={} cache_create={} cache_read={}",
        t.input,
        t.output,
        t.cache_create,
        t.cache_read,
        grand.input,
        grand.output,
        grand.cache_create,
        grand.cache_read
    );
}

fn error_response(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = serde_json::json!({
        "error": { "type": kind, "message": message }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static error response is valid")
}
