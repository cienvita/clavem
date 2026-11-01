//! Resolving the credential a client presents into a tenant and key.
//!
//! Key records are cached by key id for `cache_ttl`. The secret is
//! checked against the cached HMAC on every request, so the cache never
//! lets a wrong secret through. Disabling a key or tenant through the
//! admin API purges the cache immediately; a change made directly in the
//! database takes effect within one TTL.
//!
//! Only hits are cached. With the database down, keys already in the
//! cache keep working until their entry expires; anything else is denied.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use tracing::warn;

use crate::budget::SpendTracker;
use crate::db::{Db, KeyRecord};
use crate::keys::{self, Pepper, TokenClaims, TokenKey};

pub struct Auth {
    pub db: Db,
    pub pepper: Pepper,
    pub token_key: TokenKey,
    pub token_max_ttl: Duration,
    ttl: Duration,
    cache: Mutex<HashMap<String, (Instant, Arc<KeyRecord>)>>,
    /// Bumped by every purge. A load that started before a purge must not
    /// put what it read into the cache afterwards, or a key disabled
    /// mid-load would keep working for a TTL.
    generation: AtomicU64,
    pub spend: SpendTracker,
}

/// Who a request is from.
#[derive(Debug, Clone)]
pub struct Principal {
    pub record: Arc<KeyRecord>,
    /// Set when the request used an access token rather than the key.
    pub token: Option<TokenClaims>,
}

#[derive(Debug)]
pub enum AuthError {
    /// No credential, or one that is not a clavem key or token.
    Missing,
    /// Well-formed but wrong, unknown or expired. The reason is for logs;
    /// clients get [`AuthError::client_message`].
    Invalid(&'static str),
    /// Valid credential for a disabled key or tenant.
    Disabled(String),
    /// Could not reach the database for an uncached key.
    Unavailable(anyhow::Error),
}

impl AuthError {
    /// What a client is told. Unknown key and wrong secret read the same,
    /// so the answer does not confirm which key ids exist.
    pub fn client_message(&self) -> &'static str {
        match self {
            AuthError::Invalid("token expired") => "token expired",
            AuthError::Invalid("key expired") => "key expired",
            AuthError::Invalid(why) if why.contains("token") => "invalid token",
            AuthError::Invalid(_) => "invalid key",
            _ => "",
        }
    }
}

impl Auth {
    pub fn new(
        db: Db,
        pepper: Pepper,
        token_key: TokenKey,
        token_max_ttl: Duration,
        ttl: Duration,
    ) -> Auth {
        Auth {
            db,
            pepper,
            token_key,
            token_max_ttl,
            ttl,
            cache: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            spend: SpendTracker::default(),
        }
    }

    pub fn purge(&self) {
        let mut c = self.cache.lock().unwrap();
        self.generation.fetch_add(1, Ordering::SeqCst);
        c.clear();
    }

    async fn record(&self, key_id: &str) -> Result<Option<Arc<KeyRecord>>, AuthError> {
        if let Some((at, rec)) = self.cache.lock().unwrap().get(key_id)
            && at.elapsed() < self.ttl
        {
            return Ok(Some(rec.clone()));
        }
        let generation = self.generation.load(Ordering::SeqCst);
        let rec = match self.db.load_key(key_id).await {
            Ok(Some(r)) => Arc::new(r),
            Ok(None) => return Ok(None),
            Err(e) => return Err(AuthError::Unavailable(e)),
        };
        self.seed_spend(&rec).await;
        let mut cache = self.cache.lock().unwrap();
        if self.generation.load(Ordering::SeqCst) == generation {
            cache.insert(key_id.to_string(), (Instant::now(), rec.clone()));
        }
        Ok(Some(rec))
    }

    /// Reads current-period spend for each budget into the tracker. A
    /// failure leaves the counters as they were rather than failing auth.
    async fn seed_spend(&self, rec: &KeyRecord) {
        let now = Utc::now();
        for b in &rec.budgets {
            let start = b.period.start(now);
            match self.db.spend_since(b, start).await {
                Ok(s) => self.spend.observe(b.id, start, s),
                Err(e) => warn!("budget {}: reading spend: {e:#}", b.id),
            }
        }
    }

    /// Resolves a key string to its record, checking the secret only.
    pub async fn key(&self, presented: &str) -> Result<Arc<KeyRecord>, AuthError> {
        let parsed = keys::parse_key(presented).ok_or(AuthError::Invalid("malformed key"))?;
        let rec = self
            .record(parsed.id)
            .await?
            .ok_or(AuthError::Invalid("unknown key"))?;
        if !self.pepper.verify(parsed.secret, &rec.key.secret_hmac) {
            return Err(AuthError::Invalid("wrong key secret"));
        }
        Ok(rec)
    }

    /// Resolves whatever the client presented, key or token, and checks
    /// that the key and tenant are usable now.
    pub async fn resolve(&self, presented: Option<&str>) -> Result<Principal, AuthError> {
        let presented = presented.ok_or(AuthError::Missing)?;
        let (rec, token) = if presented.starts_with(keys::TOKEN_PREFIX) {
            let claims = keys::verify_token(&self.token_key, presented, Utc::now().timestamp())
                .map_err(|e| match e {
                    keys::TokenError::Expired => AuthError::Invalid("token expired"),
                    _ => AuthError::Invalid("invalid token"),
                })?;
            let rec = self
                .record(&claims.kid)
                .await?
                .ok_or(AuthError::Invalid("token names an unknown key"))?;
            if rec.tenant.id != claims.tid {
                return Err(AuthError::Invalid("token tenant does not match key"));
            }
            (rec, Some(claims))
        } else if presented.starts_with(keys::KEY_PREFIX) {
            (self.key(presented).await?, None)
        } else {
            return Err(AuthError::Missing);
        };
        usable(&rec)?;
        Ok(Principal { record: rec, token })
    }
}

pub fn usable(rec: &KeyRecord) -> Result<(), AuthError> {
    if !rec.tenant.enabled {
        return Err(AuthError::Disabled(format!(
            "tenant {} is disabled",
            rec.tenant.slug
        )));
    }
    if !rec.key.enabled {
        return Err(AuthError::Disabled(format!(
            "key {} is disabled",
            rec.key.id
        )));
    }
    if rec.key.expires_at.is_some_and(|t| t <= Utc::now()) {
        return Err(AuthError::Invalid("key expired"));
    }
    Ok(())
}
