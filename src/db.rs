//! Postgres access: pool, migrations, and every query clavem runs.

use std::collections::{BTreeMap, HashMap};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use rust_decimal::Decimal;
use serde::Serialize;
use serde_json::Value;
use tokio_postgres::{NoTls, Row};
use uuid::Uuid;

use crate::budget::{Budget, Period, Spend};
use crate::config::{DatabaseConfig, read_key_file};
use crate::policy::Policy;
use crate::pricing::Price;
use crate::usage::Tokens;

mod embedded {
    refinery::embed_migrations!("migrations");
}

#[derive(Clone)]
pub struct Db {
    pool: Pool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tenant {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub enabled: bool,
    pub policy: Policy,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Key {
    pub id: String,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(skip)]
    pub secret_hmac: Vec<u8>,
    pub hint: String,
    pub enabled: bool,
    pub policy: Policy,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Grant {
    pub provider: String,
    pub credential: String,
    pub priority: i32,
}

/// Everything needed to authorise a request made with one key.
#[derive(Debug, Clone)]
pub struct KeyRecord {
    pub key: Key,
    pub tenant: Tenant,
    pub grants: Vec<Grant>,
    /// Tenant-wide budgets plus this key's own.
    pub budgets: Vec<Budget>,
}

/// One metered response, as the writer stores it.
#[derive(Debug, Clone)]
pub struct UsageEvent {
    pub request_id: String,
    pub ts: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub key_id: String,
    pub provider: String,
    pub credential: String,
    pub model: String,
    pub status: i16,
    pub latency_ms: i32,
    pub tokens: Tokens,
    pub cost_usd: Option<Decimal>,
    pub price_id: Option<i64>,
    pub usage: Value,
    pub meta: Value,
}

fn policy_from(v: Value, what: &str) -> Result<Policy> {
    let p: Policy =
        serde_json::from_value(v).with_context(|| format!("stored {what} policy is invalid"))?;
    p.validate()
        .map_err(|e| anyhow::anyhow!("stored {what} policy is invalid: {e}"))?;
    Ok(p)
}

fn tenant_from(r: &Row) -> Result<Tenant> {
    Ok(Tenant {
        id: r.try_get("id")?,
        slug: r.try_get("slug")?,
        name: r.try_get("name")?,
        enabled: r.try_get("enabled")?,
        policy: policy_from(r.try_get("policy")?, "tenant")?,
        metadata: r.try_get("metadata")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn key_from(r: &Row) -> Result<Key> {
    Ok(Key {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        name: r.try_get("name")?,
        secret_hmac: r.try_get("secret_hmac")?,
        hint: r.try_get("hint")?,
        enabled: r.try_get("enabled")?,
        policy: policy_from(r.try_get("policy")?, "key")?,
        expires_at: r.try_get("expires_at")?,
        created_at: r.try_get("created_at")?,
        updated_at: r.try_get("updated_at")?,
    })
}

fn budget_from(r: &Row) -> Result<Budget> {
    let period: String = r.try_get("period")?;
    Ok(Budget {
        id: r.try_get("id")?,
        tenant_id: r.try_get("tenant_id")?,
        key_id: r.try_get("key_id")?,
        period: Period::parse(&period)
            .with_context(|| format!("unknown budget period {period:?}"))?,
        limit_usd: r.try_get("limit_usd")?,
        limit_tokens: r.try_get("limit_tokens")?,
    })
}

fn price_from(r: &Row) -> Result<Price> {
    let geo: Value = r.try_get("geo_multipliers")?;
    let geo_multipliers: BTreeMap<String, Decimal> =
        serde_json::from_value(geo).context("price.geo_multipliers must map strings to numbers")?;
    Ok(Price {
        id: r.try_get("id")?,
        provider_kind: r.try_get("provider_kind")?,
        model_pattern: r.try_get("model_pattern")?,
        speed: r.try_get("speed")?,
        min_prompt_tokens: r.try_get("min_prompt_tokens")?,
        effective_from: r.try_get("effective_from")?,
        input_usd_per_mtok: r.try_get("input_usd_per_mtok")?,
        output_usd_per_mtok: r.try_get("output_usd_per_mtok")?,
        cache_write_5m_usd_per_mtok: r.try_get("cache_write_5m_usd_per_mtok")?,
        cache_write_1h_usd_per_mtok: r.try_get("cache_write_1h_usd_per_mtok")?,
        cache_read_usd_per_mtok: r.try_get("cache_read_usd_per_mtok")?,
        web_search_usd_per_1k: r.try_get("web_search_usd_per_1k")?,
        geo_multipliers,
        note: r.try_get("note")?,
    })
}

const TENANT_COLS: &str = "id, slug, name, enabled, policy, metadata, created_at, updated_at";
const KEY_COLS: &str =
    "id, tenant_id, name, secret_hmac, hint, enabled, policy, expires_at, created_at, updated_at";
const BUDGET_COLS: &str = "id, tenant_id, key_id, period, limit_usd, limit_tokens";
const PRICE_COLS: &str = "id, provider_kind, model_pattern, speed, min_prompt_tokens, effective_from, \
    input_usd_per_mtok, output_usd_per_mtok, cache_write_5m_usd_per_mtok, cache_write_1h_usd_per_mtok, \
    cache_read_usd_per_mtok, web_search_usd_per_1k, geo_multipliers, note";

fn i64_of(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Db {
    /// Builds the pool and applies pending migrations.
    pub async fn connect(cfg: &DatabaseConfig) -> Result<Db> {
        let mut pg: tokio_postgres::Config = cfg.url.parse().context("parsing database.url")?;
        if let Some(path) = &cfg.password_file {
            let pw = read_key_file(path)
                .with_context(|| format!("reading database password from {}", path.display()))?;
            pg.password(pw);
        }
        let mgr = Manager::from_config(
            pg,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        // Bounded waits: a flood of uncached-key lookups or a dead leader
        // turns into fast 503s instead of requests queueing indefinitely.
        let pool = Pool::builder(mgr)
            .max_size(cfg.pool_size)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .wait_timeout(Some(std::time::Duration::from_secs(5)))
            .create_timeout(Some(std::time::Duration::from_secs(5)))
            .recycle_timeout(Some(std::time::Duration::from_secs(5)))
            .build()
            .context("building database pool")?;
        let db = Db { pool };
        db.migrate().await?;
        Ok(db)
    }

    async fn migrate(&self) -> Result<()> {
        let mut obj = self.pool.get().await.context("connecting to database")?;
        let client: &mut tokio_postgres::Client = &mut obj;
        let report = embedded::migrations::runner()
            .run_async(client)
            .await
            .context("running migrations")?;
        for m in report.applied_migrations() {
            tracing::info!("applied migration {}", m);
        }
        Ok(())
    }

    pub async fn ping(&self) -> Result<()> {
        self.client().await?.simple_query("SELECT 1").await?;
        Ok(())
    }

    async fn client(&self) -> Result<deadpool_postgres::Object> {
        self.pool.get().await.context("getting database connection")
    }

    // ---- auth path ------------------------------------------------------

    pub async fn load_key(&self, key_id: &str) -> Result<Option<KeyRecord>> {
        let c = self.client().await?;
        let Some(kr) = c
            .query_opt(
                &format!("SELECT {KEY_COLS} FROM virtual_key WHERE id = $1"),
                &[&key_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let key = key_from(&kr)?;
        let tr = c
            .query_one(
                &format!("SELECT {TENANT_COLS} FROM tenant WHERE id = $1"),
                &[&key.tenant_id],
            )
            .await?;
        let tenant = tenant_from(&tr)?;
        let grants = c
            .query(
                "SELECT provider, credential, priority FROM credential_grant \
                 WHERE tenant_id = $1 ORDER BY priority, provider, credential",
                &[&tenant.id],
            )
            .await?
            .iter()
            .map(|r| {
                Ok(Grant {
                    provider: r.try_get("provider")?,
                    credential: r.try_get("credential")?,
                    priority: r.try_get("priority")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let budgets = c
            .query(
                &format!(
                    "SELECT {BUDGET_COLS} FROM budget \
                     WHERE tenant_id = $1 AND (key_id IS NULL OR key_id = $2) ORDER BY id"
                ),
                &[&tenant.id, &key.id],
            )
            .await?
            .iter()
            .map(budget_from)
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(KeyRecord {
            key,
            tenant,
            grants,
            budgets,
        }))
    }

    /// Recorded spend for a budget's scope since `from` (inclusive).
    pub async fn spend_since(&self, b: &Budget, from: NaiveDate) -> Result<Spend> {
        let c = self.client().await?;
        let r = c
            .query_one(
                "SELECT COALESCE(SUM(cost_usd), 0) AS usd, \
                        COALESCE(SUM(input_tokens + output_tokens + cache_write_5m_tokens \
                                     + cache_write_1h_tokens + cache_read_tokens), 0)::bigint AS tokens \
                 FROM usage_daily \
                 WHERE tenant_id = $1 AND ($2::text IS NULL OR key_id = $2) AND day >= $3",
                &[&b.tenant_id, &b.key_id, &from],
            )
            .await?;
        Ok(Spend {
            usd: r.try_get("usd")?,
            tokens: r.try_get("tokens")?,
        })
    }

    pub async fn load_prices(&self) -> Result<Vec<Price>> {
        let c = self.client().await?;
        c.query(&format!("SELECT {PRICE_COLS} FROM price ORDER BY id"), &[])
            .await?
            .iter()
            .map(price_from)
            .collect()
    }

    // ---- writer -----------------------------------------------------------

    /// Inserts a batch and updates the daily rollup in one transaction.
    /// Events already present (same request_id) are skipped and not
    /// rolled up again, so a retried batch never double counts. Returns
    /// how many were new.
    pub async fn write_batch(&self, events: &[UsageEvent]) -> Result<usize> {
        let mut c = self.client().await?;
        let tx = c.transaction().await?;
        let insert = tx
            .prepare(
                "INSERT INTO usage_event (request_id, ts, tenant_id, key_id, provider, credential, model, \
                    status, latency_ms, input_tokens, output_tokens, cache_write_5m_tokens, \
                    cache_write_1h_tokens, cache_read_tokens, cost_usd, price_id, usage, meta) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) \
                 ON CONFLICT (request_id) DO NOTHING RETURNING 1",
            )
            .await?;
        type RollKey = (NaiveDate, Uuid, String, String, String);
        let mut roll: HashMap<RollKey, (i64, i64, Tokens, Decimal)> = HashMap::new();
        let mut inserted = 0;
        for e in events {
            let t = &e.tokens;
            let row = tx
                .query_opt(
                    &insert,
                    &[
                        &e.request_id,
                        &e.ts,
                        &e.tenant_id,
                        &e.key_id,
                        &e.provider,
                        &e.credential,
                        &e.model,
                        &e.status,
                        &e.latency_ms,
                        &i64_of(t.input),
                        &i64_of(t.output),
                        &i64_of(t.cache_write_5m),
                        &i64_of(t.cache_write_1h),
                        &i64_of(t.cache_read),
                        &e.cost_usd,
                        &e.price_id,
                        &e.usage,
                        &e.meta,
                    ],
                )
                .await?;
            if row.is_none() {
                continue;
            }
            inserted += 1;
            let k = (
                e.ts.date_naive(),
                e.tenant_id,
                e.key_id.clone(),
                e.provider.clone(),
                e.model.clone(),
            );
            let r = roll
                .entry(k)
                .or_insert((0, 0, Tokens::default(), Decimal::ZERO));
            r.0 += 1;
            if e.cost_usd.is_none() {
                r.1 += 1;
            }
            r.2.add(t);
            r.3 += e.cost_usd.unwrap_or(Decimal::ZERO);
        }
        let upsert = tx
            .prepare(
                "INSERT INTO usage_daily AS d (day, tenant_id, key_id, provider, model, requests, \
                    unpriced_requests, input_tokens, output_tokens, cache_write_5m_tokens, \
                    cache_write_1h_tokens, cache_read_tokens, cost_usd) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) \
                 ON CONFLICT (day, tenant_id, key_id, provider, model) DO UPDATE SET \
                    requests = d.requests + EXCLUDED.requests, \
                    unpriced_requests = d.unpriced_requests + EXCLUDED.unpriced_requests, \
                    input_tokens = d.input_tokens + EXCLUDED.input_tokens, \
                    output_tokens = d.output_tokens + EXCLUDED.output_tokens, \
                    cache_write_5m_tokens = d.cache_write_5m_tokens + EXCLUDED.cache_write_5m_tokens, \
                    cache_write_1h_tokens = d.cache_write_1h_tokens + EXCLUDED.cache_write_1h_tokens, \
                    cache_read_tokens = d.cache_read_tokens + EXCLUDED.cache_read_tokens, \
                    cost_usd = d.cost_usd + EXCLUDED.cost_usd",
            )
            .await?;
        for ((day, tenant, key, provider, model), (n, unpriced, t, cost)) in &roll {
            tx.execute(
                &upsert,
                &[
                    day,
                    tenant,
                    key,
                    provider,
                    model,
                    n,
                    unpriced,
                    &i64_of(t.input),
                    &i64_of(t.output),
                    &i64_of(t.cache_write_5m),
                    &i64_of(t.cache_write_1h),
                    &i64_of(t.cache_read),
                    cost,
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(inserted)
    }

    // ---- admin: tenants ---------------------------------------------------

    pub async fn create_tenant(
        &self,
        slug: &str,
        name: &str,
        policy: &Policy,
        metadata: &Value,
    ) -> Result<Tenant> {
        let c = self.client().await?;
        let r = c
            .query_one(
                &format!(
                    "INSERT INTO tenant (slug, name, policy, metadata) VALUES ($1, $2, $3, $4) \
                     RETURNING {TENANT_COLS}"
                ),
                &[&slug, &name, &serde_json::to_value(policy)?, metadata],
            )
            .await?;
        tenant_from(&r)
    }

    pub async fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let c = self.client().await?;
        c.query(
            &format!("SELECT {TENANT_COLS} FROM tenant ORDER BY slug"),
            &[],
        )
        .await?
        .iter()
        .map(tenant_from)
        .collect()
    }

    /// By uuid or slug.
    pub async fn get_tenant(&self, id_or_slug: &str) -> Result<Option<Tenant>> {
        let c = self.client().await?;
        let r = match id_or_slug.parse::<Uuid>() {
            Ok(id) => {
                c.query_opt(
                    &format!("SELECT {TENANT_COLS} FROM tenant WHERE id = $1"),
                    &[&id],
                )
                .await?
            }
            Err(_) => {
                c.query_opt(
                    &format!("SELECT {TENANT_COLS} FROM tenant WHERE slug = $1"),
                    &[&id_or_slug],
                )
                .await?
            }
        };
        r.as_ref().map(tenant_from).transpose()
    }

    pub async fn update_tenant(
        &self,
        id: Uuid,
        name: Option<&str>,
        enabled: Option<bool>,
        policy: Option<&Policy>,
        metadata: Option<&Value>,
    ) -> Result<Option<Tenant>> {
        let c = self.client().await?;
        let policy = policy.map(serde_json::to_value).transpose()?;
        let r = c
            .query_opt(
                &format!(
                    "UPDATE tenant SET name = COALESCE($2, name), enabled = COALESCE($3, enabled), \
                        policy = COALESCE($4, policy), metadata = COALESCE($5, metadata), \
                        updated_at = now() \
                     WHERE id = $1 RETURNING {TENANT_COLS}"
                ),
                &[&id, &name, &enabled, &policy, &metadata],
            )
            .await?;
        r.as_ref().map(tenant_from).transpose()
    }

    // ---- admin: keys --------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub async fn create_key(
        &self,
        id: &str,
        tenant_id: Uuid,
        name: &str,
        secret_hmac: &[u8],
        hint: &str,
        policy: &Policy,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Key> {
        let c = self.client().await?;
        let r = c
            .query_one(
                &format!(
                    "INSERT INTO virtual_key (id, tenant_id, name, secret_hmac, hint, policy, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {KEY_COLS}"
                ),
                &[&id, &tenant_id, &name, &secret_hmac, &hint, &serde_json::to_value(policy)?, &expires_at],
            )
            .await?;
        key_from(&r)
    }

    pub async fn list_keys(&self, tenant_id: Uuid) -> Result<Vec<Key>> {
        let c = self.client().await?;
        c.query(
            &format!("SELECT {KEY_COLS} FROM virtual_key WHERE tenant_id = $1 ORDER BY created_at"),
            &[&tenant_id],
        )
        .await?
        .iter()
        .map(key_from)
        .collect()
    }

    /// `expires_at`: None leaves it, Some(None) clears it.
    pub async fn update_key(
        &self,
        id: &str,
        name: Option<&str>,
        enabled: Option<bool>,
        policy: Option<&Policy>,
        expires_at: Option<Option<DateTime<Utc>>>,
    ) -> Result<Option<Key>> {
        let c = self.client().await?;
        let policy = policy.map(serde_json::to_value).transpose()?;
        let set_exp = expires_at.is_some();
        let exp = expires_at.flatten();
        let r = c
            .query_opt(
                &format!(
                    "UPDATE virtual_key SET name = COALESCE($2, name), enabled = COALESCE($3, enabled), \
                        policy = COALESCE($4, policy), \
                        expires_at = CASE WHEN $5 THEN $6 ELSE expires_at END, updated_at = now() \
                     WHERE id = $1 RETURNING {KEY_COLS}"
                ),
                &[&id, &name, &enabled, &policy, &set_exp, &exp],
            )
            .await?;
        r.as_ref().map(key_from).transpose()
    }

    // ---- admin: grants ------------------------------------------------------

    pub async fn list_grants(&self, tenant_id: Uuid) -> Result<Vec<Grant>> {
        let c = self.client().await?;
        c.query(
            "SELECT provider, credential, priority FROM credential_grant \
             WHERE tenant_id = $1 ORDER BY provider, priority, credential",
            &[&tenant_id],
        )
        .await?
        .iter()
        .map(|r| {
            Ok(Grant {
                provider: r.try_get("provider")?,
                credential: r.try_get("credential")?,
                priority: r.try_get("priority")?,
            })
        })
        .collect()
    }

    /// Replaces the tenant's grants with `grants`.
    pub async fn set_grants(&self, tenant_id: Uuid, grants: &[Grant]) -> Result<()> {
        let mut c = self.client().await?;
        let tx = c.transaction().await?;
        tx.execute(
            "DELETE FROM credential_grant WHERE tenant_id = $1",
            &[&tenant_id],
        )
        .await?;
        for g in grants {
            tx.execute(
                "INSERT INTO credential_grant (tenant_id, provider, credential, priority) VALUES ($1, $2, $3, $4)",
                &[&tenant_id, &g.provider, &g.credential, &g.priority],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    // ---- admin: budgets ------------------------------------------------------

    pub async fn create_budget(
        &self,
        tenant_id: Uuid,
        key_id: Option<&str>,
        period: Period,
        limit_usd: Option<Decimal>,
        limit_tokens: Option<i64>,
    ) -> Result<Budget> {
        let c = self.client().await?;
        if let Some(k) = key_id {
            let owner: Option<Uuid> = c
                .query_opt("SELECT tenant_id FROM virtual_key WHERE id = $1", &[&k])
                .await?
                .map(|r| r.get(0));
            if owner != Some(tenant_id) {
                bail!("key {k} does not belong to this tenant");
            }
        }
        let r = c
            .query_one(
                &format!(
                    "INSERT INTO budget (tenant_id, key_id, period, limit_usd, limit_tokens) \
                     VALUES ($1, $2, $3, $4, $5) RETURNING {BUDGET_COLS}"
                ),
                &[
                    &tenant_id,
                    &key_id,
                    &period.as_str(),
                    &limit_usd,
                    &limit_tokens,
                ],
            )
            .await?;
        budget_from(&r)
    }

    pub async fn list_budgets(&self, tenant_id: Uuid) -> Result<Vec<Budget>> {
        let c = self.client().await?;
        c.query(
            &format!("SELECT {BUDGET_COLS} FROM budget WHERE tenant_id = $1 ORDER BY id"),
            &[&tenant_id],
        )
        .await?
        .iter()
        .map(budget_from)
        .collect()
    }

    pub async fn delete_budget(&self, id: Uuid) -> Result<Option<Uuid>> {
        let c = self.client().await?;
        Ok(c.query_opt(
            "DELETE FROM budget WHERE id = $1 RETURNING tenant_id",
            &[&id],
        )
        .await?
        .map(|r| r.get(0)))
    }

    // ---- admin: prices -------------------------------------------------------

    pub async fn create_price(&self, p: &Price) -> Result<Price> {
        let c = self.client().await?;
        let r = c
            .query_one(
                &format!(
                    "INSERT INTO price (provider_kind, model_pattern, speed, min_prompt_tokens, effective_from, \
                        input_usd_per_mtok, output_usd_per_mtok, cache_write_5m_usd_per_mtok, \
                        cache_write_1h_usd_per_mtok, cache_read_usd_per_mtok, web_search_usd_per_1k, \
                        geo_multipliers, note) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING {PRICE_COLS}"
                ),
                &[
                    &p.provider_kind,
                    &p.model_pattern,
                    &p.speed,
                    &p.min_prompt_tokens,
                    &p.effective_from,
                    &p.input_usd_per_mtok,
                    &p.output_usd_per_mtok,
                    &p.cache_write_5m_usd_per_mtok,
                    &p.cache_write_1h_usd_per_mtok,
                    &p.cache_read_usd_per_mtok,
                    &p.web_search_usd_per_1k,
                    &serde_json::to_value(&p.geo_multipliers)?,
                    &p.note,
                ],
            )
            .await?;
        price_from(&r)
    }

    // ---- admin: usage ----------------------------------------------------------

    /// Daily rollup rows for a tenant between two dates inclusive, summed
    /// over the dimensions not in `group_by`.
    pub async fn usage(
        &self,
        tenant_id: Uuid,
        from: NaiveDate,
        to: NaiveDate,
        group_by: &[UsageDim],
    ) -> Result<Vec<Value>> {
        let cols: Vec<&str> = group_by.iter().map(|d| d.column()).collect();
        let select = if cols.is_empty() {
            String::new()
        } else {
            format!("{}, ", cols.join(", "))
        };
        let group = if cols.is_empty() {
            String::new()
        } else {
            format!("GROUP BY {} ORDER BY {}", cols.join(", "), cols.join(", "))
        };
        let sql = format!(
            "SELECT {select} SUM(requests)::bigint AS requests, SUM(unpriced_requests)::bigint AS unpriced_requests, \
                SUM(input_tokens)::bigint AS input_tokens, SUM(output_tokens)::bigint AS output_tokens, \
                SUM(cache_write_5m_tokens)::bigint AS cache_write_5m_tokens, \
                SUM(cache_write_1h_tokens)::bigint AS cache_write_1h_tokens, \
                SUM(cache_read_tokens)::bigint AS cache_read_tokens, SUM(cost_usd) AS cost_usd \
             FROM usage_daily WHERE tenant_id = $1 AND day BETWEEN $2 AND $3 {group}"
        );
        let c = self.client().await?;
        let rows = c.query(&sql, &[&tenant_id, &from, &to]).await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let requests: Option<i64> = r.try_get("requests")?;
            if requests.is_none() {
                continue; // no rows at all in the ungrouped case
            }
            let mut m = serde_json::Map::new();
            for d in group_by {
                let v = match d {
                    UsageDim::Day => serde_json::to_value(r.try_get::<_, NaiveDate>("day")?)?,
                    _ => Value::String(r.try_get::<_, String>(d.column())?),
                };
                m.insert(d.column().to_string(), v);
            }
            for f in [
                "requests",
                "unpriced_requests",
                "input_tokens",
                "output_tokens",
                "cache_write_5m_tokens",
                "cache_write_1h_tokens",
                "cache_read_tokens",
            ] {
                m.insert(
                    f.into(),
                    Value::from(r.try_get::<_, Option<i64>>(f)?.unwrap_or(0)),
                );
            }
            let cost: Option<Decimal> = r.try_get("cost_usd")?;
            m.insert(
                "cost_usd".into(),
                Value::String(cost.unwrap_or_default().normalize().to_string()),
            );
            out.push(Value::Object(m));
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UsageDim {
    Day,
    Key,
    Provider,
    Model,
}

impl UsageDim {
    pub fn parse(s: &str) -> Option<UsageDim> {
        match s {
            "day" => Some(UsageDim::Day),
            "key" | "key_id" => Some(UsageDim::Key),
            "provider" => Some(UsageDim::Provider),
            "model" => Some(UsageDim::Model),
            _ => None,
        }
    }

    fn column(self) -> &'static str {
        match self {
            UsageDim::Day => "day",
            UsageDim::Key => "key_id",
            UsageDim::Provider => "provider",
            UsageDim::Model => "model",
        }
    }
}
