//! End-to-end tests over a real socket: gateway in front of a mock upstream.

use std::sync::Arc;

use axum::Json;
use axum::extract::Request;
use axum::response::Response;
use axum::routing::{any, get};
use clavem::provider::{Kind, Provider, Registry};
use clavem::proxy::{AppState, app};
use serde_json::{Value, json};

/// Echoes what the upstream received, with an Anthropic-shaped `model` and
/// `usage` tail so the usage sniffer has something to read.
async fn echo(req: Request) -> Json<Value> {
    let (parts, body) = req.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let headers: serde_json::Map<String, Value> = parts
        .headers
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), json!(v.to_str().unwrap_or(""))))
        .collect();
    Json(json!({
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&body),
        "model": "claude-haiku-4-5",
        "usage": {
            "input_tokens": 11,
            "output_tokens": 7,
            "cache_creation_input_tokens": 3,
            "cache_read_input_tokens": 5,
        },
    }))
}

async fn sse() -> Response {
    let events = concat!(
        "event: message_start\n",
        r#"data: {"type":"message_start","message":{"model":"claude-sonnet-5","usage":{"input_tokens":100,"output_tokens":1,"cache_read_input_tokens":40}}}"#,
        "\n\n",
        "event: content_block_delta\n",
        r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}"#,
        "\n\n",
        "event: message_delta\n",
        r#"data: {"type":"message_delta","usage":{"output_tokens":25}}"#,
        "\n\n",
    );
    Response::builder()
        .header("content-type", "text/event-stream")
        .body(axum::body::Body::from(events))
        .unwrap()
}

async fn serve(router: axum::Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("http://{addr}")
}

struct Harness {
    base: String,
    state: Arc<AppState>,
    client: reqwest::Client,
}

impl Harness {
    /// Three provider instances, all pointing at one mock upstream, so the
    /// per-kind credential handling is what varies between them.
    async fn start() -> Harness {
        let upstream = serve(
            axum::Router::new()
                .route("/sse", get(sse))
                .fallback(any(echo)),
        )
        .await;

        let state = Arc::new(AppState::new(Registry::new(vec![
            Provider::new("anthropic", Kind::Anthropic, &upstream, "sk-ant-real").unwrap(),
            Provider::new("xai", Kind::Xai, &upstream, "xai-real").unwrap(),
            Provider::new("azure-eu", Kind::Azure, &upstream, "azure-real").unwrap(),
        ])));
        let base = serve(app(state.clone())).await;
        Harness {
            base,
            state,
            client: reqwest::Client::new(),
        }
    }

    async fn post(&self, path: &str, body: &str) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}{path}", self.base))
            .header("content-type", "application/json")
            .header("x-api-key", "client-placeholder")
            .header("authorization", "Bearer client-placeholder")
            .body(body.to_string())
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap();
        let json = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"));
        (status, json)
    }

    fn totals(&self) -> Vec<(String, u64, u64)> {
        let t = self.state.totals.lock().unwrap();
        t.by_model
            .iter()
            .map(|(k, v)| (k.clone(), v.input, v.output))
            .collect()
    }
}

#[tokio::test]
async fn forwards_rest_of_path_and_query_verbatim() {
    let h = Harness::start().await;
    let (status, got) = h
        .post("/anthropic/v1/messages?beta=tools", r#"{"model":"x"}"#)
        .await;
    assert_eq!(status, 200);
    assert_eq!(got["path"], "/v1/messages");
    assert_eq!(got["query"], "beta=tools");
    assert_eq!(got["body"], r#"{"model":"x"}"#);
}

#[tokio::test]
async fn substitutes_the_real_credential_per_kind() {
    let h = Harness::start().await;

    let (_, got) = h.post("/anthropic/v1/messages", "{}").await;
    assert_eq!(got["headers"]["x-api-key"], "sk-ant-real");
    assert_eq!(got["headers"]["anthropic-version"], "2023-06-01");
    assert!(got["headers"]["authorization"].is_null());

    let (_, got) = h.post("/xai/v1/chat/completions", "{}").await;
    assert_eq!(got["headers"]["authorization"], "Bearer xai-real");
    assert!(got["headers"]["x-api-key"].is_null());

    let (_, got) = h.post("/azure-eu/openai/deployments/gpt/chat", "{}").await;
    assert_eq!(got["headers"]["api-key"], "azure-real");
    assert!(got["headers"]["authorization"].is_null());
}

#[tokio::test]
async fn unknown_prefix_is_rejected_before_any_upstream_call() {
    let h = Harness::start().await;
    let (status, got) = h.post("/openai/v1/chat/completions", "{}").await;
    assert_eq!(status, 404);
    assert_eq!(got["error"]["type"], "unknown_provider");
}

#[tokio::test]
async fn meters_anthropic_json_responses_by_provider_and_model() {
    let h = Harness::start().await;
    h.post("/anthropic/v1/messages", "{}").await;
    h.post("/anthropic/v1/messages", "{}").await;
    assert_eq!(
        h.totals(),
        vec![("anthropic/claude-haiku-4-5".to_string(), 22, 14)]
    );
    assert_eq!(h.state.totals.lock().unwrap().requests, 2);
}

#[tokio::test]
async fn meters_streaming_responses() {
    let h = Harness::start().await;
    let resp = h
        .client
        .get(format!("{}/anthropic/sse", h.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let body = resp.text().await.unwrap();
    assert!(body.contains("message_delta"), "{body}");

    // output_tokens comes from message_delta, the rest from message_start.
    let totals = h.totals();
    assert_eq!(totals.len(), 1);
    assert_eq!(totals[0].0, "anthropic/claude-sonnet-5");
    assert_eq!((totals[0].1, totals[0].2), (100, 25));
    assert_eq!(
        h.state.totals.lock().unwrap().by_model["anthropic/claude-sonnet-5"].cache_read,
        40
    );
}

#[tokio::test]
async fn openai_shaped_kinds_are_not_metered_yet() {
    let h = Harness::start().await;
    h.post("/xai/v1/chat/completions", "{}").await;
    assert!(h.totals().is_empty());
}
