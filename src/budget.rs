//! Budgets and the in-memory spend counters that enforce them.
//!
//! Enforcement is pre-flight and approximate: a request is refused when
//! the period's recorded spend is already at or over a limit. Requests in
//! flight when a limit is crossed all complete, so spend can overshoot by
//! their combined cost. This is cost control, not a security boundary.
//!
//! Postgres (`usage_daily`) is the source of truth. Counters are seeded
//! from it when an auth entry loads, bumped locally as events are costed,
//! and merged with `max` on every reload, so a reload never forgets local
//! spend the writer has not flushed yet, and spend recorded by another
//! instance shows up within one cache TTL.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Datelike, NaiveDate, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Period {
    Day,
    Month,
}

impl Period {
    pub fn as_str(self) -> &'static str {
        match self {
            Period::Day => "day",
            Period::Month => "month",
        }
    }

    pub fn parse(s: &str) -> Option<Period> {
        match s {
            "day" => Some(Period::Day),
            "month" => Some(Period::Month),
            _ => None,
        }
    }

    /// First day of the period containing `t`, UTC.
    pub fn start(self, t: DateTime<Utc>) -> NaiveDate {
        let d = t.date_naive();
        match self {
            Period::Day => d,
            Period::Month => d.with_day(1).expect("day 1 exists"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Budget {
    pub id: Uuid,
    pub tenant_id: Uuid,
    /// None: applies to every key of the tenant.
    pub key_id: Option<String>,
    pub period: Period,
    pub limit_usd: Option<Decimal>,
    pub limit_tokens: Option<i64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Spend {
    pub usd: Decimal,
    pub tokens: i64,
}

#[derive(Debug, PartialEq)]
pub struct Exceeded {
    pub budget_id: Uuid,
    pub message: String,
}

impl Budget {
    pub fn check(&self, spend: Spend) -> Result<(), Exceeded> {
        let scope = match &self.key_id {
            Some(k) => format!("key {k}"),
            None => "tenant".to_string(),
        };
        if let Some(limit) = self.limit_usd
            && spend.usd >= limit
        {
            return Err(Exceeded {
                budget_id: self.id,
                message: format!(
                    "{scope} {} budget of ${limit} reached (spent ${})",
                    self.period.as_str(),
                    spend.usd.round_dp(6)
                ),
            });
        }
        if let Some(limit) = self.limit_tokens
            && spend.tokens >= limit
        {
            return Err(Exceeded {
                budget_id: self.id,
                message: format!(
                    "{scope} {} budget of {limit} tokens reached (spent {})",
                    self.period.as_str(),
                    spend.tokens
                ),
            });
        }
        Ok(())
    }
}

/// Spend per (budget, period start).
#[derive(Default)]
pub struct SpendTracker {
    inner: Mutex<HashMap<(Uuid, NaiveDate), Spend>>,
}

impl SpendTracker {
    pub fn get(&self, budget: Uuid, period_start: NaiveDate) -> Spend {
        self.inner
            .lock()
            .unwrap()
            .get(&(budget, period_start))
            .copied()
            .unwrap_or_default()
    }

    /// Merge a value read from Postgres.
    pub fn observe(&self, budget: Uuid, period_start: NaiveDate, db: Spend) {
        let mut m = self.inner.lock().unwrap();
        let e = m.entry((budget, period_start)).or_default();
        e.usd = e.usd.max(db.usd);
        e.tokens = e.tokens.max(db.tokens);
    }

    pub fn add(&self, budget: Uuid, period_start: NaiveDate, usd: Decimal, tokens: i64) {
        let mut m = self.inner.lock().unwrap();
        let e = m.entry((budget, period_start)).or_default();
        e.usd += usd;
        e.tokens += tokens;
    }

    /// Drop counters for periods that ended, so the map does not grow.
    pub fn prune_before(&self, cutoff: NaiveDate) {
        self.inner
            .lock()
            .unwrap()
            .retain(|(_, start), _| *start >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn budget(usd: Option<&str>, tokens: Option<i64>) -> Budget {
        Budget {
            id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            key_id: None,
            period: Period::Month,
            limit_usd: usd.map(|s| s.parse().unwrap()),
            limit_tokens: tokens,
        }
    }

    #[test]
    fn period_starts() {
        let t = Utc.with_ymd_and_hms(2026, 11, 17, 23, 59, 59).unwrap();
        assert_eq!(
            Period::Day.start(t),
            NaiveDate::from_ymd_opt(2026, 11, 17).unwrap()
        );
        assert_eq!(
            Period::Month.start(t),
            NaiveDate::from_ymd_opt(2026, 11, 1).unwrap()
        );
    }

    #[test]
    fn usd_limit_is_inclusive() {
        let b = budget(Some("1.00"), None);
        assert!(
            b.check(Spend {
                usd: "0.99".parse().unwrap(),
                tokens: 0
            })
            .is_ok()
        );
        let e = b
            .check(Spend {
                usd: "1".parse().unwrap(),
                tokens: 0,
            })
            .unwrap_err();
        assert!(
            e.message.contains("tenant month budget of $1.00 reached"),
            "{}",
            e.message
        );
    }

    #[test]
    fn token_limit() {
        let b = budget(None, Some(1000));
        assert!(
            b.check(Spend {
                usd: Decimal::ZERO,
                tokens: 999
            })
            .is_ok()
        );
        assert!(
            b.check(Spend {
                usd: Decimal::ZERO,
                tokens: 1000
            })
            .is_err()
        );
    }

    #[test]
    fn either_limit_trips() {
        let b = budget(Some("5"), Some(10));
        assert!(
            b.check(Spend {
                usd: Decimal::ZERO,
                tokens: 10
            })
            .is_err()
        );
        assert!(
            b.check(Spend {
                usd: "5".parse().unwrap(),
                tokens: 0
            })
            .is_err()
        );
    }

    #[test]
    fn tracker_merges_with_max_and_adds() {
        let t = SpendTracker::default();
        let id = Uuid::now_v7();
        let p = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        t.add(id, p, "0.5".parse().unwrap(), 100);
        // Postgres has not seen the local spend yet.
        t.observe(
            id,
            p,
            Spend {
                usd: "0.2".parse().unwrap(),
                tokens: 50,
            },
        );
        assert_eq!(
            t.get(id, p),
            Spend {
                usd: "0.5".parse().unwrap(),
                tokens: 100
            }
        );
        // Another instance spent more.
        t.observe(
            id,
            p,
            Spend {
                usd: "2".parse().unwrap(),
                tokens: 900,
            },
        );
        assert_eq!(
            t.get(id, p),
            Spend {
                usd: "2".parse().unwrap(),
                tokens: 900
            }
        );
        t.prune_before(NaiveDate::from_ymd_opt(2026, 12, 1).unwrap());
        assert_eq!(t.get(id, p), Spend::default());
    }
}
