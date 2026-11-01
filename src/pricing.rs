//! Price lookup and cost at ingest.
//!
//! A price row matches an event when its provider kind and speed match,
//! its model pattern matches (exact, or prefix ending in `*`), its
//! `effective_from` is at or before the event, and its
//! `min_prompt_tokens` is at or below the event's prompt length. Of the
//! matches, the longest pattern wins, then the highest prompt tier, then
//! the latest `effective_from`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::policy::pattern_match;
use crate::usage::Tokens;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Price {
    pub id: i64,
    pub provider_kind: String,
    pub model_pattern: String,
    pub speed: String,
    pub min_prompt_tokens: i64,
    pub effective_from: DateTime<Utc>,
    pub input_usd_per_mtok: Decimal,
    pub output_usd_per_mtok: Decimal,
    pub cache_write_5m_usd_per_mtok: Decimal,
    pub cache_write_1h_usd_per_mtok: Decimal,
    pub cache_read_usd_per_mtok: Decimal,
    pub web_search_usd_per_1k: Decimal,
    /// inference_geo -> multiplier on token prices.
    pub geo_multipliers: BTreeMap<String, Decimal>,
    pub note: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct PriceBook {
    prices: Vec<Price>,
}

/// What a price lookup needs to know about an event.
pub struct Billable<'a> {
    pub provider_kind: &'a str,
    pub model: &'a str,
    pub speed: Option<&'a str>,
    pub inference_geo: Option<&'a str>,
    pub at: DateTime<Utc>,
    pub tokens: &'a Tokens,
}

impl PriceBook {
    pub fn new(prices: Vec<Price>) -> PriceBook {
        PriceBook { prices }
    }

    pub fn len(&self) -> usize {
        self.prices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prices.is_empty()
    }

    pub fn find(&self, b: &Billable) -> Option<&Price> {
        let speed = b.speed.unwrap_or("standard");
        let prompt = b.tokens.prompt() as i64;
        self.prices
            .iter()
            .filter(|p| {
                p.provider_kind == b.provider_kind
                    && p.speed == speed
                    && p.effective_from <= b.at
                    && p.min_prompt_tokens <= prompt
                    && pattern_match(&p.model_pattern, b.model)
            })
            .max_by_key(|p| {
                (
                    p.model_pattern.trim_end_matches('*').len(),
                    !p.model_pattern.ends_with('*'),
                    p.min_prompt_tokens,
                    p.effective_from,
                )
            })
    }

    /// Cost in USD and the price row used, or None when nothing matches.
    /// The literal model `unknown` is never priced.
    pub fn cost(&self, b: &Billable) -> Option<(Decimal, i64)> {
        if b.model == "unknown" {
            return None;
        }
        let p = self.find(b)?;
        Some((cost_with(p, b), p.id))
    }
}

pub fn cost_with(p: &Price, b: &Billable) -> Decimal {
    let t = b.tokens;
    let mtok = Decimal::from(1_000_000);
    let d = |n: u64| Decimal::from(n);
    let tokens_usd = d(t.input) * p.input_usd_per_mtok
        + d(t.output) * p.output_usd_per_mtok
        + d(t.cache_write_5m) * p.cache_write_5m_usd_per_mtok
        + d(t.cache_write_1h) * p.cache_write_1h_usd_per_mtok
        + d(t.cache_read) * p.cache_read_usd_per_mtok;
    let geo = b
        .inference_geo
        .and_then(|g| p.geo_multipliers.get(g))
        .copied()
        .unwrap_or(Decimal::ONE);
    let searches = d(t.web_search_requests) * p.web_search_usd_per_1k / Decimal::from(1000);
    (tokens_usd * geo / mtok + searches).round_dp(10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn dec(s: &str) -> Decimal {
        s.parse().unwrap()
    }

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn price(
        id: i64,
        pattern: &str,
        speed: &str,
        min_prompt: i64,
        from: DateTime<Utc>,
        input: Decimal,
        output: Decimal,
    ) -> Price {
        Price {
            id,
            provider_kind: "anthropic".into(),
            model_pattern: pattern.into(),
            speed: speed.into(),
            min_prompt_tokens: min_prompt,
            effective_from: from,
            input_usd_per_mtok: input,
            output_usd_per_mtok: output,
            cache_write_5m_usd_per_mtok: input * dec("1.25"),
            cache_write_1h_usd_per_mtok: input * dec("2"),
            cache_read_usd_per_mtok: input / dec("10"),
            web_search_usd_per_1k: dec("10"),
            geo_multipliers: [("us".to_string(), dec("1.1"))].into(),
            note: None,
        }
    }

    fn book() -> PriceBook {
        let epoch = at(1970, 1, 1);
        PriceBook::new(vec![
            price(
                1,
                "claude-opus-5*",
                "standard",
                0,
                epoch,
                dec("5"),
                dec("25"),
            ),
            price(
                2,
                "claude-opus-5-5*",
                "standard",
                0,
                epoch,
                dec("4"),
                dec("20"),
            ),
            price(3, "claude-opus-5-5*", "fast", 0, epoch, dec("8"), dec("40")),
            price(
                4,
                "claude-haiku-5-5*",
                "standard",
                0,
                epoch,
                dec("0.10"),
                dec("0.50"),
            ),
            price(
                5,
                "claude-haiku-5-5*",
                "standard",
                100_001,
                epoch,
                dec("0.50"),
                dec("2.50"),
            ),
            price(
                6,
                "claude-opus-5-5*",
                "standard",
                0,
                at(2027, 1, 1),
                dec("3"),
                dec("15"),
            ),
        ])
    }

    fn bill<'a>(model: &'a str, tokens: &'a Tokens) -> Billable<'a> {
        Billable {
            provider_kind: "anthropic",
            model,
            speed: None,
            inference_geo: None,
            at: at(2026, 11, 1),
            tokens,
        }
    }

    fn toks(input: u64, output: u64) -> Tokens {
        Tokens {
            input,
            output,
            ..Tokens::default()
        }
    }

    #[test]
    fn longest_pattern_wins() {
        let t = toks(1, 1);
        assert_eq!(book().find(&bill("claude-opus-5-5", &t)).unwrap().id, 2);
        assert_eq!(book().find(&bill("claude-opus-5", &t)).unwrap().id, 1);
        assert_eq!(
            book().find(&bill("claude-opus-5-20260101", &t)).unwrap().id,
            1
        );
    }

    #[test]
    fn effective_from_is_respected() {
        let t = toks(1, 1);
        let mut b = bill("claude-opus-5-5", &t);
        assert_eq!(book().find(&b).unwrap().id, 2);
        b.at = at(2027, 2, 1);
        assert_eq!(book().find(&b).unwrap().id, 6);
    }

    #[test]
    fn fast_mode_uses_fast_row() {
        let t = toks(1_000_000, 1_000_000);
        let mut b = bill("claude-opus-5-5", &t);
        b.speed = Some("fast");
        assert_eq!(book().cost(&b).unwrap(), (dec("48"), 3));
        b.model = "claude-opus-5";
        assert!(
            book().cost(&b).is_none(),
            "no fast row for opus-5 in this book"
        );
    }

    #[test]
    fn haiku_long_prompt_tier_counts_cache_tokens() {
        let short = Tokens {
            input: 50_000,
            cache_read: 50_000,
            ..Tokens::default()
        };
        assert_eq!(
            book().find(&bill("claude-haiku-5-5", &short)).unwrap().id,
            4
        );
        let long = Tokens {
            input: 50_000,
            cache_read: 50_001,
            ..Tokens::default()
        };
        assert_eq!(book().find(&bill("claude-haiku-5-5", &long)).unwrap().id, 5);
    }

    #[test]
    fn cost_covers_every_token_kind() {
        let t = Tokens {
            input: 1_000_000,
            output: 1_000_000,
            cache_write_5m: 1_000_000,
            cache_write_1h: 1_000_000,
            cache_read: 1_000_000,
            cache_create: 2_000_000,
            web_search_requests: 3,
        };
        // 4 + 20 + 5 + 8 + 0.4 + 0.03
        assert_eq!(
            book().cost(&bill("claude-opus-5-5", &t)).unwrap().0,
            dec("37.43")
        );
    }

    #[test]
    fn geo_multiplier_applies_to_tokens_not_searches() {
        let t = Tokens {
            input: 1_000_000,
            web_search_requests: 1000,
            ..Tokens::default()
        };
        let mut b = bill("claude-opus-5-5", &t);
        b.inference_geo = Some("us");
        assert_eq!(book().cost(&b).unwrap().0, dec("14.4"));
        b.inference_geo = Some("global");
        assert_eq!(book().cost(&b).unwrap().0, dec("14"));
    }

    #[test]
    fn unknown_and_unmatched_models_are_unpriced() {
        let t = toks(10, 10);
        assert!(book().cost(&bill("unknown", &t)).is_none());
        assert!(book().cost(&bill("gpt-5", &t)).is_none());
    }

    #[test]
    fn small_request_cost() {
        // 13 in, 4 out on Haiku 5.5: 13*0.10/1e6 + 4*0.50/1e6
        let t = toks(13, 4);
        assert_eq!(
            book().cost(&bill("claude-haiku-5-5", &t)).unwrap().0,
            dec("0.0000033")
        );
    }
}
