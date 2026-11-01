use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use anyhow::{Context, Result};
use async_stream::stream;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::response::Response;
use axum::routing::{any, post};
use chrono::Utc;
use futures_util::StreamExt;
use http::{HeaderMap, StatusCode};
use rust_decimal::Decimal;
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{Auth, AuthError, Principal, usable};
use crate::db::UsageEvent;
use crate::keys::{self, TokenClaims};
use crate::policy::{self, Layer, Policy};
use crate::pricing::{Billable, PriceBook};
use crate::provider::{Kind, Provider, Registry, strip_response_headers};
use crate::usage::{Metered, Sniffer, Tokens, Totals};
use crate::writer::Writer;

/// Cap on a buffered client request body. Bodies are read whole because
/// adapters need to inspect and (for some kinds) rewrite them.
const MAX_REQUEST_BODY: usize = 64 * 1024 * 1024;

/// Default lifetime of an access token when the caller does not ask.
const DEFAULT_TOKEN_TTL: u64 = 900;

pub struct AppState {
    pub client: reqwest::Client,
    pub registry: Registry,
    pub totals: Mutex<Totals>,
    /// None: open mode, no client auth and nothing persisted.
    pub backend: Option<Backend>,
}

/// Everything that needs the database.
pub struct Backend {
    pub auth: Arc<Auth>,
    pub prices: RwLock<PriceBook>,
    pub writer: Writer,
}

impl AppState {
    pub fn new(registry: Registry) -> AppState {
        AppState {
            client: reqwest::Client::new(),
            registry,
            totals: Mutex::new(Totals::default()),
            backend: None,
        }
    }

    pub fn with_backend(registry: Registry, backend: Backend) -> AppState {
        AppState {
            backend: Some(backend),
            ..AppState::new(registry)
        }
    }
}

pub fn app(state: Arc<AppState>) -> Router {
    // Everything not claimed by a gateway-owned route is a pass-through.
    // Provider names cannot start with '_', so /_clavem never shadows one.
    Router::new()
        .route("/_clavem/v1/token", post(token))
        .fallback(any(forward))
        .with_state(state)
}

async fn forward(State(state): State<Arc<AppState>>, req: Request) -> Response {
    match do_forward(state, req).await {
        Ok(resp) => resp,
        Err(e) => {
            // The detail can name internal upstream hosts; it stays in the log.
            error!("forward error: {e:#}");
            error_response(
                StatusCode::BAD_GATEWAY,
                "api_error",
                "clavem could not complete the upstream request",
            )
        }
    }
}

/// The credential a client sent, from the slot its SDK uses.
fn client_credential(headers: &HeaderMap) -> Option<&str> {
    if let Some(v) = headers.get("x-api-key").and_then(|v| v.to_str().ok()) {
        return Some(v.trim());
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim)
}

fn auth_error_response(e: AuthError) -> Response {
    match e {
        AuthError::Missing => error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "missing clavem key: send a clv_ key or clvt_ token in x-api-key or Authorization: Bearer",
        ),
        AuthError::Invalid(_) => error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            e.client_message(),
        ),
        AuthError::Disabled(why) => error_response(StatusCode::FORBIDDEN, "permission_error", &why),
        AuthError::Unavailable(err) => {
            error!("auth: database unavailable: {err:#}");
            error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "api_error",
                "clavem cannot verify credentials right now",
            )
        }
    }
}

/// Top-level fields of a request body that policies and pricing look at.
#[derive(Debug, Default, PartialEq)]
struct BodyFields {
    model: Option<String>,
    max_tokens: Option<u64>,
    speed: Option<String>,
}

/// Reads `model`, `max_tokens` and `speed` from a JSON object body.
/// Duplicate top-level keys are refused: serde keeps the last one, and an
/// upstream that keeps the first would see a different model than the
/// policy checked.
fn body_fields(body: &[u8]) -> Result<BodyFields, String> {
    use serde::de::{Deserializer as _, IgnoredAny, MapAccess, Visitor};

    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = BodyFields;

        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("a JSON object")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<BodyFields, A::Error> {
            use serde::de::Error;
            let mut seen = std::collections::HashSet::new();
            let mut out = BodyFields::default();
            while let Some(k) = map.next_key::<String>()? {
                if !seen.insert(k.clone()) {
                    return Err(A::Error::custom(format!("duplicate key {k:?}")));
                }
                match k.as_str() {
                    "model" => {
                        let v: Value = map.next_value()?;
                        out.model = Some(
                            v.as_str()
                                .ok_or_else(|| A::Error::custom("model must be a string"))?
                                .to_string(),
                        );
                    }
                    "max_tokens" => {
                        let v: Value = map.next_value()?;
                        if !v.is_null() {
                            out.max_tokens = Some(v.as_u64().ok_or_else(|| {
                                A::Error::custom("max_tokens must be a non-negative integer")
                            })?);
                        }
                    }
                    "speed" => {
                        let v: Value = map.next_value()?;
                        out.speed = v.as_str().map(str::to_string);
                    }
                    _ => {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
            }
            Ok(out)
        }
    }

    if body.is_empty() {
        return Ok(BodyFields::default());
    }
    let mut de = serde_json::Deserializer::from_slice(body);
    let out = (&mut de)
        .deserialize_map(V)
        .map_err(|e| format!("request body: {e}"))?;
    de.end().map_err(|e| format!("request body: {e}"))?;
    Ok(out)
}

/// Tenant, key and token policies, in that order.
fn layers(p: &Principal) -> Vec<(Layer, &Policy)> {
    let mut v = vec![
        (Layer::Tenant, &p.record.tenant.policy),
        (Layer::Key, &p.record.key.policy),
    ];
    if let Some(Some(pol)) = p.token.as_ref().map(|t| t.pol.as_ref()) {
        v.push((Layer::Token, pol));
    }
    v
}

/// Lowest-priority grant for this provider whose credential exists.
fn pick_credential(p: &Principal, provider: &Provider) -> Option<String> {
    p.record
        .grants
        .iter()
        .filter(|g| g.provider == provider.name && provider.has_credential(&g.credential))
        .min_by_key(|g| (g.priority, g.credential.clone()))
        .map(|g| g.credential.clone())
}

async fn do_forward(state: Arc<AppState>, req: Request) -> Result<Response> {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();

    let Some((provider, rest)) = state.registry.route(&path) else {
        info!("{} {path} -> no provider", parts.method);
        // In open mode the list helps whoever is setting clavem up. With
        // client auth on, this answer comes before auth, so say less.
        let msg = if state.backend.is_some() {
            format!("no provider matches {path}")
        } else {
            format!(
                "no provider matches {path}; configured: {}",
                state
                    .registry
                    .providers()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            "unknown_provider",
            &msg,
        ));
    };
    if !policy::path_is_canonical(&rest) {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            "path contains empty, dot or encoded-separator segments",
        ));
    }

    let principal = match &state.backend {
        None => None,
        Some(b) => match b.auth.resolve(client_credential(&parts.headers)).await {
            Ok(p) => Some(p),
            Err(e) => {
                info!("{} {path} -> refused: {e:?}", parts.method);
                return Ok(auth_error_response(e));
            }
        },
    };

    let body_bytes = match axum::body::to_bytes(body, MAX_REQUEST_BODY).await {
        Ok(b) => b,
        Err(e) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                &format!("reading request body: {e}"),
            ));
        }
    };

    let credential = match &principal {
        None => provider.first_credential().to_string(),
        Some(p) => {
            let backend = state.backend.as_ref().expect("principal implies backend");
            let layers = layers(p);
            // Budgets are only enforceable where clavem can meter.
            if !p.record.budgets.is_empty() && !provider_is_metered(&provider) {
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    &format!(
                        "provider {:?} is not metered by clavem yet, and tenant {} has budgets",
                        provider.name, p.record.tenant.slug
                    ),
                ));
            }
            let model_policy = layers.iter().any(|(_, pol)| pol.needs_body());
            let usd_budget = p.record.budgets.iter().any(|b| b.limit_usd.is_some());
            let fields = if (model_policy || usd_budget) && !body_bytes.is_empty() {
                match body_fields(&body_bytes) {
                    Ok(f) => f,
                    Err(msg) => {
                        return Ok(error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid_request_error",
                            &msg,
                        ));
                    }
                }
            } else {
                BodyFields::default()
            };
            // A body without a top-level model (batches, for one) would
            // slip past a model policy, so refuse it rather than guess.
            if model_policy && !body_bytes.is_empty() && fields.model.is_none() {
                return Ok(error_response(
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    "a model policy applies, and the request body has no top-level model",
                ));
            }
            // An unpriced model would count as $0 against a USD budget.
            if usd_budget && let Some(model) = &fields.model {
                let zero = Tokens::default();
                let priced = backend
                    .prices
                    .read()
                    .unwrap()
                    .find(&Billable {
                        provider_kind: provider.kind.as_str(),
                        model,
                        speed: fields.speed.as_deref(),
                        inference_geo: None,
                        at: Utc::now(),
                        tokens: &zero,
                    })
                    .is_some();
                if !priced {
                    return Ok(error_response(
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        &format!(
                            "model {model:?} (speed {}) has no price, and a USD budget applies",
                            fields.speed.as_deref().unwrap_or("standard")
                        ),
                    ));
                }
            }
            let req = policy::Request {
                provider: &provider.name,
                path: &rest,
                model: fields.model.as_deref(),
                max_tokens: fields.max_tokens,
            };
            for (layer, pol) in &layers {
                if let Err(d) = pol.check(*layer, &req) {
                    info!(
                        "{} {path} -> denied for {}: {}",
                        parts.method, p.record.key.id, d.0
                    );
                    return Ok(error_response(
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        &d.0,
                    ));
                }
            }
            let now = Utc::now();
            for b in &p.record.budgets {
                let spend = backend.auth.spend.get(b.id, b.period.start(now));
                if let Err(x) = b.check(spend) {
                    info!(
                        "{} {path} -> over budget for {}: {}",
                        parts.method, p.record.key.id, x.message
                    );
                    return Ok(error_response(
                        StatusCode::PAYMENT_REQUIRED,
                        "billing_error",
                        &x.message,
                    ));
                }
            }
            match pick_credential(p, &provider) {
                Some(c) => c,
                None => {
                    return Ok(error_response(
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        &format!(
                            "tenant {} has no upstream credential for provider {:?}",
                            p.record.tenant.slug, provider.name
                        ),
                    ));
                }
            }
        }
    };

    let url = provider.upstream_url(&rest, parts.uri.query());
    match &principal {
        Some(p) => info!(
            "{} {path} -> {url} (tenant {} key {} credential {credential})",
            parts.method, p.record.tenant.slug, p.record.key.id
        ),
        None => info!("{} {path} -> {url}", parts.method),
    }

    let upstream = state
        .client
        .request(parts.method.clone(), &url)
        .headers(provider.upstream_headers_with(&parts.headers, &credential))
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
    let upstream_request_id = upstream
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let mut resp = Response::builder().status(status);
    if let Some(headers) = resp.headers_mut() {
        headers.extend(upstream.headers().clone());
        strip_response_headers(headers);
        if state.backend.is_some() {
            // Identifies the organisation behind a shared upstream
            // credential; tenants have no use for it.
            headers.remove("anthropic-organization-id");
        }
    }

    let sniff = sniffer_for(&provider, status, &content_type);
    let ctx = RecordCtx {
        state: state.clone(),
        provider: provider.clone(),
        credential,
        principal,
        rest,
        status,
        stream: content_type.contains("text/event-stream"),
        request_id: upstream_request_id,
        started,
    };
    // The guard records on drop. When a client disconnects, hyper drops
    // this stream mid-loop and nothing after the loop would run; the
    // tokens were still generated and billed upstream, so they must still
    // be recorded and counted against budgets.
    let mut guard = RecordOnDrop {
        sniff,
        ctx: Some(ctx),
    };
    let body_stream = stream! {
        let mut up = upstream.bytes_stream();
        while let Some(item) = up.next().await {
            if let (Some(s), Ok(b)) = (guard.sniff.as_mut(), &item) {
                s.feed(b);
            }
            yield item;
        }
        drop(guard);
    };

    Ok(resp.body(Body::from_stream(body_stream))?)
}

struct RecordOnDrop {
    sniff: Option<Sniffer>,
    ctx: Option<RecordCtx>,
}

impl Drop for RecordOnDrop {
    fn drop(&mut self) {
        if let (Some(ctx), Some(m)) = (
            self.ctx.take(),
            self.sniff.take().and_then(Sniffer::finalize),
        ) {
            ctx.record(m);
        }
    }
}

struct RecordCtx {
    state: Arc<AppState>,
    provider: Arc<Provider>,
    credential: String,
    principal: Option<Principal>,
    rest: String,
    status: StatusCode,
    stream: bool,
    request_id: Option<String>,
    started: Instant,
}

impl RecordCtx {
    fn record(self, m: Metered) {
        let grand =
            self.state
                .totals
                .lock()
                .unwrap()
                .record(&self.provider.name, &m.model, &m.tokens);
        let (Some(backend), Some(p)) = (&self.state.backend, &self.principal) else {
            report_request(&self.provider.name, &m.model, &m.tokens, &grand, "");
            return;
        };
        let ts = Utc::now();
        let priced = backend.prices.read().unwrap().cost(&Billable {
            provider_kind: self.provider.kind.as_str(),
            model: &m.model,
            speed: m.usage_str("speed"),
            inference_geo: m.usage_str("inference_geo"),
            at: ts,
            tokens: &m.tokens,
        });
        let (cost, price_id) = match priced {
            Some((c, id)) => (Some(c), Some(id)),
            None => {
                warn!(
                    "unpriced usage: provider kind {} model {:?} speed {:?}",
                    self.provider.kind.as_str(),
                    m.model,
                    m.usage_str("speed")
                );
                (None, None)
            }
        };
        let tokens_total = i64::try_from(m.tokens.total()).unwrap_or(i64::MAX);
        for b in &p.record.budgets {
            backend.auth.spend.add(
                b.id,
                b.period.start(ts),
                cost.unwrap_or(Decimal::ZERO),
                tokens_total,
            );
        }
        let extra = format!(
            " tenant={} key={} cost={}",
            p.record.tenant.slug,
            p.record.key.id,
            cost.map(|c| format!("${}", c.normalize()))
                .unwrap_or_else(|| "unpriced".into())
        );
        report_request(&self.provider.name, &m.model, &m.tokens, &grand, &extra);

        let mut meta = json!({ "path": self.rest, "stream": self.stream });
        if let Some(t) = &p.token {
            meta["token_jti"] = json!(t.jti);
        }
        if m.partial {
            meta["partial"] = json!(true);
        }
        backend.writer.send(UsageEvent {
            request_id: self
                .request_id
                .unwrap_or_else(|| format!("clavem_{}", Uuid::now_v7())),
            ts,
            tenant_id: p.record.tenant.id,
            key_id: p.record.key.id.clone(),
            provider: self.provider.name.clone(),
            credential: self.credential,
            model: m.model,
            status: self.status.as_u16() as i16,
            latency_ms: i32::try_from(self.started.elapsed().as_millis()).unwrap_or(i32::MAX),
            tokens: m.tokens,
            cost_usd: cost,
            price_id,
            usage: m.usage,
            meta,
        });
    }
}

fn provider_is_metered(provider: &Provider) -> bool {
    matches!(provider.kind, Kind::Anthropic)
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

fn report_request(provider: &str, model: &str, t: &Tokens, grand: &Tokens, extra: &str) {
    info!(
        "[{provider}/{model}] in={} out={} cache_create={} cache_read={} | total in={} out={} cache_create={} cache_read={}{extra}",
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

/// Anthropic's error envelope, which Anthropic SDKs parse.
pub fn error_response(status: StatusCode, kind: &str, message: &str) -> Response {
    let body = json!({
        "type": "error",
        "error": { "type": kind, "message": message }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("static error response is valid")
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRequest {
    ttl_seconds: Option<u64>,
    policy: Option<Policy>,
}

/// POST /_clavem/v1/token: exchange a virtual key for a short-lived token.
async fn token(State(state): State<Arc<AppState>>, headers: HeaderMap, body: Bytes) -> Response {
    let Some(backend) = &state.backend else {
        return error_response(
            StatusCode::NOT_FOUND,
            "not_found_error",
            "token exchange needs a database",
        );
    };
    let presented = client_credential(&headers);
    if presented.is_some_and(|p| p.starts_with(keys::TOKEN_PREFIX)) {
        return error_response(
            StatusCode::UNAUTHORIZED,
            "authentication_error",
            "a token cannot be exchanged for another token; use the key",
        );
    }
    let rec = match presented {
        None => return auth_error_response(AuthError::Missing),
        Some(k) => match backend.auth.key(k).await {
            Ok(r) => r,
            Err(e) => return auth_error_response(e),
        },
    };
    if let Err(e) = usable(&rec) {
        return auth_error_response(e);
    }
    let req: TokenRequest = if body.is_empty() {
        TokenRequest::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(r) => r,
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    &format!("{e}"),
                );
            }
        }
    };
    let max = backend.auth.token_max_ttl.as_secs();
    let ttl = req.ttl_seconds.unwrap_or(DEFAULT_TOKEN_TTL.min(max));
    if ttl == 0 || ttl > max {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("ttl_seconds must be between 1 and {max}"),
        );
    }
    if let Some(p) = &req.policy
        && let Err(e) = p.validate()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request_error",
            &format!("policy: {e}"),
        );
    }
    let now = Utc::now().timestamp();
    let mut exp = now + ttl as i64;
    // A token never outlives its key.
    if let Some(key_exp) = rec.key.expires_at {
        exp = exp.min(key_exp.timestamp());
    }
    let claims = TokenClaims {
        v: 1,
        kid: rec.key.id.clone(),
        tid: rec.tenant.id,
        iat: now,
        exp,
        jti: Uuid::now_v7(),
        pol: req.policy,
    };
    let token = keys::sign_token(&backend.auth.token_key, &claims);
    info!(
        "token {} issued for tenant {} key {}, expires in {}s",
        claims.jti,
        rec.tenant.slug,
        rec.key.id,
        exp - now
    );
    let body = json!({
        "token": token,
        "token_type": "bearer",
        "expires_in": exp - now,
        "expires_at": chrono::DateTime::from_timestamp(exp, 0),
        "jti": claims.jti,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("token response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn credential_from_either_slot() {
        let mut h = HeaderMap::new();
        assert_eq!(client_credential(&h), None);
        h.insert("authorization", HeaderValue::from_static("Bearer clv_x"));
        assert_eq!(client_credential(&h), Some("clv_x"));
        h.insert("x-api-key", HeaderValue::from_static("clvt_y"));
        assert_eq!(client_credential(&h), Some("clvt_y"));
    }

    #[test]
    fn body_fields_reads_model_and_max_tokens() {
        assert_eq!(body_fields(b"").unwrap(), BodyFields::default());
        assert_eq!(
            body_fields(
                br#"{"model":"m","max_tokens":5,"speed":"fast","messages":[{"model":"x"}]}"#
            )
            .unwrap(),
            BodyFields {
                model: Some("m".into()),
                max_tokens: Some(5),
                speed: Some("fast".into()),
            }
        );
        assert!(body_fields(b"not json").is_err());
        assert!(body_fields(b"[1]").is_err());
        assert!(body_fields(br#"{"max_tokens":-1}"#).is_err());
        assert!(body_fields(br#"{"model":5}"#).is_err());
        assert!(body_fields(br#"{"model":"a"} trailing"#).is_err());
    }

    #[test]
    fn body_fields_refuses_duplicate_top_level_keys() {
        let e =
            body_fields(br#"{"model":"claude-haiku-5-5","model":"claude-opus-5-5"}"#).unwrap_err();
        assert!(e.contains("duplicate key"), "{e}");
        // Nested duplicates are not our concern.
        assert!(body_fields(br#"{"model":"m","metadata":{"a":1,"a":2}}"#).is_ok());
    }
}
