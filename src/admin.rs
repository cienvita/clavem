//! Management API, on its own listener. Bearer-token auth with a single
//! admin token read from a file. JSON in, JSON out.
//!
//! ```text
//! GET   /v1/credentials                    upstream credentials from config
//! GET   /v1/tenants                        list
//! POST  /v1/tenants                        {slug, name, policy?, metadata?}
//! GET   /v1/tenants/{tenant}               by id or slug
//! PATCH /v1/tenants/{tenant}               {name?, enabled?, policy?, metadata?}
//! GET   /v1/tenants/{tenant}/keys
//! POST  /v1/tenants/{tenant}/keys          {name, policy?, expires_at?} -> key shown once
//! PATCH /v1/keys/{id}                      {name?, enabled?, policy?, expires_at?}
//! GET   /v1/tenants/{tenant}/grants
//! PUT   /v1/tenants/{tenant}/grants        [{provider, credential, priority?}]
//! GET   /v1/tenants/{tenant}/budgets       with current-period spend
//! POST  /v1/tenants/{tenant}/budgets       {period, limit_usd?, limit_tokens?, key_id?}
//! DELETE /v1/budgets/{id}
//! GET   /v1/prices
//! POST  /v1/prices                         new row; prices are never edited
//! GET   /v1/tenants/{tenant}/usage?from=&to=&group_by=day,model,key,provider
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{FromRequest, FromRequestParts, Path, Query, Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use http::StatusCode;
use rust_decimal::Decimal;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use subtle::ConstantTimeEq;
use tracing::{error, info};
use uuid::Uuid;

use crate::budget::Period;
use crate::db::{Grant, Tenant, UsageDim};
use crate::keys;
use crate::policy::Policy;
use crate::pricing::{Price, PriceBook};
use crate::proxy::AppState;

pub struct AdminState {
    pub app: Arc<AppState>,
    pub token: String,
}

type S = State<Arc<AdminState>>;

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/v1/credentials", get(credentials))
        .route("/v1/tenants", get(list_tenants).post(create_tenant))
        .route("/v1/tenants/{tenant}", get(get_tenant).patch(update_tenant))
        .route("/v1/tenants/{tenant}/keys", get(list_keys).post(create_key))
        .route("/v1/keys/{id}", patch(update_key))
        .route(
            "/v1/tenants/{tenant}/grants",
            get(list_grants).put(set_grants),
        )
        .route(
            "/v1/tenants/{tenant}/budgets",
            get(list_budgets).post(create_budget),
        )
        .route("/v1/budgets/{id}", delete(delete_budget))
        .route("/v1/prices", get(list_prices).post(create_price))
        .route("/v1/tenants/{tenant}/usage", get(usage))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state)
}

async fn require_token(State(st): S, req: Request, next: Next) -> Response {
    let ok = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| t.as_bytes().ct_eq(st.token.as_bytes()).into());
    if !ok {
        return err(StatusCode::UNAUTHORIZED, "admin token required");
    }
    next.run(req).await
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

/// `Json` whose rejection is a JSON 400 rather than axum's plain text.
struct J<T>(T);

impl<St: Send + Sync, T: DeserializeOwned> FromRequest<St> for J<T> {
    type Rejection = Response;

    async fn from_request(req: Request, state: &St) -> Result<Self, Response> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(J(v)),
            Err(r) => Err(err(StatusCode::BAD_REQUEST, r.body_text())),
        }
    }
}

/// `Query` with the same treatment.
struct Q<T>(T);

impl<St: Send + Sync, T: DeserializeOwned> FromRequestParts<St> for Q<T> {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &St,
    ) -> Result<Self, Response> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(v)) => Ok(Q(v)),
            Err(r) => Err(err(StatusCode::BAD_REQUEST, r.body_text())),
        }
    }
}

fn internal(e: anyhow::Error) -> Response {
    // Unique and foreign-key violations are client errors worth naming.
    if let Some(db) = e
        .chain()
        .find_map(|c| c.downcast_ref::<tokio_postgres::Error>())
        && let Some(code) = db.code()
    {
        let msg = db
            .as_db_error()
            .map(|d| d.message().to_string())
            .unwrap_or_default();
        if *code == tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
            return err(StatusCode::CONFLICT, msg);
        }
        if *code == tokio_postgres::error::SqlState::CHECK_VIOLATION
            || *code == tokio_postgres::error::SqlState::FOREIGN_KEY_VIOLATION
        {
            return err(StatusCode::BAD_REQUEST, msg);
        }
    }
    error!("admin: {e:#}");
    err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
}

fn backend(st: &AdminState) -> &crate::proxy::Backend {
    st.app
        .backend
        .as_ref()
        .expect("admin API runs only with a database")
}

#[allow(clippy::result_large_err)]
fn check_policy(p: &Policy) -> Result<(), Response> {
    p.validate()
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("policy: {e}")))
}

#[allow(clippy::result_large_err)]
async fn tenant(st: &AdminState, id: &str) -> Result<Tenant, Response> {
    match backend(st).auth.db.get_tenant(id).await {
        Ok(Some(t)) => Ok(t),
        Ok(None) => Err(err(StatusCode::NOT_FOUND, format!("no tenant {id:?}"))),
        Err(e) => Err(internal(e)),
    }
}

macro_rules! tri {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(r) => return r,
        }
    };
}

// ---- credentials -------------------------------------------------------------

async fn credentials(State(st): S) -> Response {
    let out: Vec<Value> = st
        .app
        .registry
        .providers()
        .map(|p| {
            json!({
                "provider": p.name,
                "kind": p.kind.as_str(),
                "credentials": p.credential_names().collect::<Vec<_>>(),
            })
        })
        .collect();
    Json(out).into_response()
}

// ---- tenants -----------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTenant {
    slug: String,
    name: String,
    #[serde(default)]
    policy: Policy,
    #[serde(default = "empty_object")]
    metadata: Value,
}

fn empty_object() -> Value {
    json!({})
}

async fn list_tenants(State(st): S) -> Response {
    match backend(&st).auth.db.list_tenants().await {
        Ok(t) => Json(t).into_response(),
        Err(e) => internal(e),
    }
}

async fn create_tenant(State(st): S, J(b): J<NewTenant>) -> Response {
    tri!(check_policy(&b.policy));
    if !b.metadata.is_object() {
        return err(StatusCode::BAD_REQUEST, "metadata must be an object");
    }
    match backend(&st)
        .auth
        .db
        .create_tenant(&b.slug, &b.name, &b.policy, &b.metadata)
        .await
    {
        Ok(t) => {
            info!("admin: created tenant {} ({})", t.slug, t.id);
            (StatusCode::CREATED, Json(t)).into_response()
        }
        Err(e) => internal(e),
    }
}

async fn get_tenant(State(st): S, Path(id): Path<String>) -> Response {
    Json(tri!(tenant(&st, &id).await)).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantPatch {
    name: Option<String>,
    enabled: Option<bool>,
    policy: Option<Policy>,
    metadata: Option<Value>,
}

async fn update_tenant(State(st): S, Path(id): Path<String>, J(b): J<TenantPatch>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    if let Some(p) = &b.policy {
        tri!(check_policy(p));
    }
    if b.metadata.as_ref().is_some_and(|m| !m.is_object()) {
        return err(StatusCode::BAD_REQUEST, "metadata must be an object");
    }
    let be = backend(&st);
    match be
        .auth
        .db
        .update_tenant(
            t.id,
            b.name.as_deref(),
            b.enabled,
            b.policy.as_ref(),
            b.metadata.as_ref(),
        )
        .await
    {
        Ok(Some(t)) => {
            be.auth.purge();
            info!("admin: updated tenant {}", t.slug);
            Json(t).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, "tenant vanished"),
        Err(e) => internal(e),
    }
}

// ---- keys ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewKey {
    name: String,
    #[serde(default)]
    policy: Policy,
    expires_at: Option<DateTime<Utc>>,
}

async fn list_keys(State(st): S, Path(id): Path<String>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    match backend(&st).auth.db.list_keys(t.id).await {
        Ok(k) => Json(k).into_response(),
        Err(e) => internal(e),
    }
}

async fn create_key(State(st): S, Path(id): Path<String>, J(b): J<NewKey>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    tri!(check_policy(&b.policy));
    if b.expires_at.is_some_and(|e| e <= Utc::now()) {
        return err(StatusCode::BAD_REQUEST, "expires_at is in the past");
    }
    let be = backend(&st);
    let nk = match keys::generate_key(&be.auth.pepper) {
        Ok(k) => k,
        Err(e) => return internal(e),
    };
    match be
        .auth
        .db
        .create_key(
            &nk.id,
            t.id,
            &b.name,
            &nk.secret_hmac,
            &nk.hint,
            &b.policy,
            b.expires_at,
        )
        .await
    {
        Ok(k) => {
            info!("admin: created key {} for tenant {}", k.id, t.slug);
            let mut v = serde_json::to_value(&k).expect("key serializes");
            v["key"] = json!(nk.full);
            (StatusCode::CREATED, Json(v)).into_response()
        }
        Err(e) => internal(e),
    }
}

/// Distinguishes an absent field from an explicit null.
fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Some(Option::deserialize(d)?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPatch {
    name: Option<String>,
    enabled: Option<bool>,
    policy: Option<Policy>,
    #[serde(default, deserialize_with = "double_option")]
    expires_at: Option<Option<DateTime<Utc>>>,
}

async fn update_key(State(st): S, Path(id): Path<String>, J(b): J<KeyPatch>) -> Response {
    if let Some(p) = &b.policy {
        tri!(check_policy(p));
    }
    let be = backend(&st);
    match be
        .auth
        .db
        .update_key(
            &id,
            b.name.as_deref(),
            b.enabled,
            b.policy.as_ref(),
            b.expires_at,
        )
        .await
    {
        Ok(Some(k)) => {
            be.auth.purge();
            info!("admin: updated key {}", k.id);
            Json(k).into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, format!("no key {id:?}")),
        Err(e) => internal(e),
    }
}

// ---- grants ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantIn {
    provider: String,
    credential: String,
    #[serde(default)]
    priority: i32,
}

async fn list_grants(State(st): S, Path(id): Path<String>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    match backend(&st).auth.db.list_grants(t.id).await {
        Ok(g) => Json(g).into_response(),
        Err(e) => internal(e),
    }
}

async fn set_grants(State(st): S, Path(id): Path<String>, J(b): J<Vec<GrantIn>>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    let mut grants = Vec::with_capacity(b.len());
    for g in b {
        match st.app.registry.get(&g.provider) {
            Some(p) if p.has_credential(&g.credential) => {}
            Some(_) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "provider {:?} has no credential {:?}",
                        g.provider, g.credential
                    ),
                );
            }
            None => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!("no provider {:?}", g.provider),
                );
            }
        }
        grants.push(Grant {
            provider: g.provider,
            credential: g.credential,
            priority: g.priority,
        });
    }
    let be = backend(&st);
    match be.auth.db.set_grants(t.id, &grants).await {
        Ok(()) => {
            be.auth.purge();
            info!("admin: tenant {} now has {} grants", t.slug, grants.len());
            Json(grants).into_response()
        }
        Err(e) => internal(e),
    }
}

// ---- budgets ----------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBudget {
    period: Period,
    limit_usd: Option<Decimal>,
    limit_tokens: Option<i64>,
    key_id: Option<String>,
}

async fn list_budgets(State(st): S, Path(id): Path<String>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    let be = backend(&st);
    let budgets = match be.auth.db.list_budgets(t.id).await {
        Ok(b) => b,
        Err(e) => return internal(e),
    };
    let now = Utc::now();
    let mut out = Vec::with_capacity(budgets.len());
    for b in budgets {
        let start = b.period.start(now);
        let spend = match be.auth.db.spend_since(&b, start).await {
            Ok(s) => s,
            Err(e) => return internal(e),
        };
        let mut v = serde_json::to_value(&b).expect("budget serializes");
        v["period_start"] = json!(start);
        v["spent_usd"] = json!(spend.usd.normalize().to_string());
        v["spent_tokens"] = json!(spend.tokens);
        v["exceeded"] = json!(b.check(spend).is_err());
        out.push(v);
    }
    Json(out).into_response()
}

async fn create_budget(State(st): S, Path(id): Path<String>, J(b): J<NewBudget>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    if b.limit_usd.is_none() && b.limit_tokens.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "set limit_usd, limit_tokens or both",
        );
    }
    if b.limit_usd.is_some_and(|d| d.is_sign_negative()) || b.limit_tokens.is_some_and(|n| n < 0) {
        return err(StatusCode::BAD_REQUEST, "limits must be non-negative");
    }
    let be = backend(&st);
    match be
        .auth
        .db
        .create_budget(
            t.id,
            b.key_id.as_deref(),
            b.period,
            b.limit_usd,
            b.limit_tokens,
        )
        .await
    {
        Ok(bud) => {
            be.auth.purge();
            info!("admin: created budget {} for tenant {}", bud.id, t.slug);
            (StatusCode::CREATED, Json(bud)).into_response()
        }
        Err(e) if e.to_string().contains("does not belong") => {
            err(StatusCode::BAD_REQUEST, e.to_string())
        }
        Err(e) => internal(e),
    }
}

async fn delete_budget(State(st): S, Path(id): Path<Uuid>) -> Response {
    let be = backend(&st);
    match be.auth.db.delete_budget(id).await {
        Ok(Some(_)) => {
            be.auth.purge();
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(None) => err(StatusCode::NOT_FOUND, format!("no budget {id}")),
        Err(e) => internal(e),
    }
}

// ---- prices -------------------------------------------------------------------------

async fn list_prices(State(st): S) -> Response {
    match backend(&st).auth.db.load_prices().await {
        Ok(p) => Json(p).into_response(),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewPrice {
    #[serde(default = "anthropic")]
    provider_kind: String,
    model_pattern: String,
    #[serde(default = "standard")]
    speed: String,
    #[serde(default)]
    min_prompt_tokens: i64,
    effective_from: Option<DateTime<Utc>>,
    input_usd_per_mtok: Decimal,
    output_usd_per_mtok: Decimal,
    cache_write_5m_usd_per_mtok: Decimal,
    cache_write_1h_usd_per_mtok: Decimal,
    cache_read_usd_per_mtok: Decimal,
    #[serde(default)]
    web_search_usd_per_1k: Decimal,
    #[serde(default)]
    geo_multipliers: BTreeMap<String, Decimal>,
    note: Option<String>,
}

fn anthropic() -> String {
    "anthropic".into()
}

fn standard() -> String {
    "standard".into()
}

async fn create_price(State(st): S, J(b): J<NewPrice>) -> Response {
    if b.model_pattern.is_empty()
        || b.model_pattern
            .find('*')
            .is_some_and(|i| i != b.model_pattern.len() - 1)
    {
        return err(
            StatusCode::BAD_REQUEST,
            "model_pattern: exact id, or a prefix ending in '*'",
        );
    }
    let p = Price {
        id: 0,
        provider_kind: b.provider_kind,
        model_pattern: b.model_pattern,
        speed: b.speed,
        min_prompt_tokens: b.min_prompt_tokens,
        effective_from: b.effective_from.unwrap_or_else(Utc::now),
        input_usd_per_mtok: b.input_usd_per_mtok,
        output_usd_per_mtok: b.output_usd_per_mtok,
        cache_write_5m_usd_per_mtok: b.cache_write_5m_usd_per_mtok,
        cache_write_1h_usd_per_mtok: b.cache_write_1h_usd_per_mtok,
        cache_read_usd_per_mtok: b.cache_read_usd_per_mtok,
        web_search_usd_per_1k: b.web_search_usd_per_1k,
        geo_multipliers: b.geo_multipliers,
        note: b.note,
    };
    let be = backend(&st);
    match be.auth.db.create_price(&p).await {
        Ok(p) => {
            if let Err(e) = reload_prices(&st.app).await {
                error!("admin: reloading prices after insert: {e:#}");
            }
            info!("admin: added price {} for {}", p.id, p.model_pattern);
            (StatusCode::CREATED, Json(p)).into_response()
        }
        Err(e) => internal(e),
    }
}

pub async fn reload_prices(app: &AppState) -> anyhow::Result<usize> {
    let be = app.backend.as_ref().expect("prices need a database");
    let prices = be.auth.db.load_prices().await?;
    let n = prices.len();
    *be.prices.write().unwrap() = PriceBook::new(prices);
    Ok(n)
}

// ---- usage ------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageQuery {
    from: Option<NaiveDate>,
    to: Option<NaiveDate>,
    group_by: Option<String>,
}

async fn usage(State(st): S, Path(id): Path<String>, Q(q): Q<UsageQuery>) -> Response {
    let t = tri!(tenant(&st, &id).await);
    let today = Utc::now().date_naive();
    let from = q
        .from
        .unwrap_or_else(|| today.with_day(1).expect("day 1 exists"));
    let to = q.to.unwrap_or(today);
    if from > to {
        return err(StatusCode::BAD_REQUEST, "from is after to");
    }
    let mut dims = Vec::new();
    for g in q
        .group_by
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
    {
        match UsageDim::parse(g.trim()) {
            Some(d) if !dims.contains(&d) => dims.push(d),
            Some(_) => {}
            None => {
                return err(
                    StatusCode::BAD_REQUEST,
                    format!("group_by: unknown dimension {g:?}; use day, key, provider, model"),
                );
            }
        }
    }
    match backend(&st).auth.db.usage(t.id, from, to, &dims).await {
        Ok(rows) => {
            Json(json!({ "tenant": t.slug, "from": from, "to": to, "data": rows })).into_response()
        }
        Err(e) => internal(e),
    }
}
