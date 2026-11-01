use std::collections::BTreeMap;

use bytes::Bytes;
use serde_json::{Map, Value};

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
    /// All cache writes, `cache_write_5m + cache_write_1h`.
    pub cache_create: u64,
    pub cache_read: u64,
    pub cache_write_5m: u64,
    pub cache_write_1h: u64,
    pub web_search_requests: u64,
}

impl Tokens {
    pub fn add(&mut self, other: &Tokens) {
        self.input += other.input;
        self.output += other.output;
        self.cache_create += other.cache_create;
        self.cache_read += other.cache_read;
        self.cache_write_5m += other.cache_write_5m;
        self.cache_write_1h += other.cache_write_1h;
        self.web_search_requests += other.web_search_requests;
    }

    /// Everything that counts toward a token budget.
    pub fn total(&self) -> u64 {
        self.input + self.output + self.cache_create + self.cache_read
    }

    /// Prompt length as Anthropic's long-context pricing counts it.
    pub fn prompt(&self) -> u64 {
        self.input + self.cache_create + self.cache_read
    }
}

/// What a sniffer extracts from one response.
#[derive(Debug, Clone)]
pub struct Metered {
    pub model: String,
    pub tokens: Tokens,
    /// The upstream usage object, merged across stream events. Stored
    /// as-is so fields clavem does not know about yet are not lost.
    pub usage: Value,
    /// A stream that ended before `message_delta`, usually because the
    /// client hung up. Output is then a lower bound: at least one token
    /// per content delta seen.
    pub partial: bool,
}

impl Metered {
    pub fn usage_str(&self, field: &str) -> Option<&str> {
        self.usage.get(field).and_then(Value::as_str)
    }
}

#[derive(Debug, Default)]
pub struct Totals {
    /// Keyed by `provider/model`, so the same model served by two provider
    /// instances stays separate.
    pub by_model: BTreeMap<String, Tokens>,
    pub grand: Tokens,
    pub requests: u64,
}

impl Totals {
    pub fn record(&mut self, provider: &str, model: &str, t: &Tokens) -> Tokens {
        self.by_model
            .entry(format!("{provider}/{model}"))
            .or_default()
            .add(t);
        self.grand.add(t);
        self.requests += 1;
        self.grand
    }

    pub fn print(&self) {
        if self.by_model.is_empty() {
            println!("clavem: no usage recorded");
            return;
        }
        println!("clavem totals ({} requests):", self.requests);
        println!(
            "  {:<40} {:>10} {:>10} {:>14} {:>12}",
            "provider/model", "input", "output", "cache_create", "cache_read"
        );
        for (model, t) in &self.by_model {
            println!(
                "  {:<40} {:>10} {:>10} {:>14} {:>12}",
                model, t.input, t.output, t.cache_create, t.cache_read
            );
        }
        println!(
            "  {:<40} {:>10} {:>10} {:>14} {:>12}",
            "TOTAL",
            self.grand.input,
            self.grand.output,
            self.grand.cache_create,
            self.grand.cache_read
        );
    }
}

/// Sniffs an Anthropic Messages API response, either streaming SSE or a single JSON.
pub struct Sniffer {
    is_sse: bool,
    leftover: Vec<u8>,
    json_buf: Vec<u8>,
    model: Option<String>,
    usage: Map<String, Value>,
    deltas: u64,
    saw_message_delta: bool,
}

/// Fields that `message_delta` may report as 0 when it means "unchanged".
const STICKY_COUNTS: &[&str] = &[
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
];

impl Sniffer {
    pub fn new(content_type: &str) -> Self {
        let is_sse = content_type.contains("text/event-stream");
        Self {
            is_sse,
            leftover: Vec::new(),
            json_buf: Vec::new(),
            model: None,
            usage: Map::new(),
            deltas: 0,
            saw_message_delta: false,
        }
    }

    pub fn feed(&mut self, chunk: &Bytes) {
        if !self.is_sse {
            self.json_buf.extend_from_slice(chunk);
            return;
        }
        self.leftover.extend_from_slice(chunk);
        while let Some(end) = find_event_boundary(&self.leftover) {
            let event: Vec<u8> = self.leftover.drain(..end).collect();
            self.process_event(&event);
        }
    }

    pub fn finalize(mut self) -> Option<Metered> {
        if !self.is_sse {
            let v: Value = serde_json::from_slice(&self.json_buf).ok()?;
            let model = v.get("model")?.as_str()?.to_string();
            let usage = v.get("usage")?.clone();
            return Some(Metered {
                model,
                tokens: read_usage(&usage),
                usage,
                partial: false,
            });
        }
        // A stream that never got as far as message_start has nothing to
        // record. With no message_delta the message_start usage stands.
        if self.model.is_none() && self.usage.is_empty() {
            return None;
        }
        let model = self.model.take().unwrap_or_else(|| "unknown".into());
        let usage = Value::Object(std::mem::take(&mut self.usage));
        let mut tokens = read_usage(&usage);
        let partial = !self.saw_message_delta;
        if partial {
            tokens.output = tokens.output.max(self.deltas);
        }
        Some(Metered {
            model,
            tokens,
            usage,
            partial,
        })
    }

    fn process_event(&mut self, raw: &[u8]) {
        let s = match std::str::from_utf8(raw) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut event: Option<&str> = None;
        let mut data: Option<&str> = None;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("event:") {
                event = Some(v.trim());
            } else if let Some(v) = line.strip_prefix("data:") {
                data = Some(v.trim_start());
            }
        }
        let (Some(event), Some(data)) = (event, data) else {
            return;
        };
        let json: Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return,
        };
        match event {
            "message_start" => {
                if let Some(m) = json.pointer("/message/model").and_then(|v| v.as_str()) {
                    self.model = Some(m.to_string());
                }
                if let Some(Value::Object(u)) = json.pointer("/message/usage") {
                    self.usage = u.clone();
                }
            }
            "content_block_delta" => self.deltas += 1,
            "message_delta" => {
                self.saw_message_delta = true;
                if let Some(Value::Object(u)) = json.pointer("/usage") {
                    merge_delta(&mut self.usage, u);
                }
            }
            _ => {}
        }
    }
}

/// `message_delta` usage is cumulative, but older API versions omit or
/// zero the input-side counts, so a zero there never overwrites a value
/// `message_start` reported.
fn merge_delta(into: &mut Map<String, Value>, delta: &Map<String, Value>) {
    for (k, v) in delta {
        if v.is_null() {
            continue;
        }
        if STICKY_COUNTS.contains(&k.as_str()) && v.as_u64() == Some(0) {
            continue;
        }
        if k == "cache_creation"
            && v.as_object()
                .is_some_and(|o| o.values().all(|x| x.as_u64() == Some(0)))
        {
            continue;
        }
        into.insert(k.clone(), v.clone());
    }
}

fn read_usage(v: &Value) -> Tokens {
    let n = |p: &str| v.pointer(p).and_then(Value::as_u64).unwrap_or(0);
    let cache_create = n("/cache_creation_input_tokens");
    let (w5, w1) = if v.pointer("/cache_creation").is_some_and(Value::is_object) {
        (
            n("/cache_creation/ephemeral_5m_input_tokens"),
            n("/cache_creation/ephemeral_1h_input_tokens"),
        )
    } else {
        // No breakdown: the default TTL is 5 minutes.
        (cache_create, 0)
    };
    Tokens {
        input: n("/input_tokens"),
        output: n("/output_tokens"),
        cache_create: cache_create.max(w5 + w1),
        cache_read: n("/cache_read_input_tokens"),
        cache_write_5m: w5,
        cache_write_1h: w1,
        web_search_requests: n("/server_tool_use/web_search_requests"),
    }
}

fn find_event_boundary(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' && buf[i + 1] == b'\n' {
            return Some(i + 2);
        }
        if i + 3 < buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sse(events: &[(&str, Value)]) -> Bytes {
        let mut s = String::new();
        for (e, d) in events {
            s.push_str(&format!("event: {e}\ndata: {d}\n\n"));
        }
        Bytes::from(s)
    }

    #[test]
    fn json_body_with_cache_breakdown() {
        let mut s = Sniffer::new("application/json");
        s.feed(&Bytes::from(
            json!({
                "model": "claude-haiku-5-5",
                "usage": {
                    "input_tokens": 10, "output_tokens": 4,
                    "cache_creation_input_tokens": 30, "cache_read_input_tokens": 50,
                    "cache_creation": {"ephemeral_5m_input_tokens": 10, "ephemeral_1h_input_tokens": 20},
                    "server_tool_use": {"web_search_requests": 2},
                    "service_tier": "standard", "inference_geo": "us", "speed": "standard"
                }
            })
            .to_string(),
        ));
        let m = s.finalize().unwrap();
        assert_eq!(m.model, "claude-haiku-5-5");
        assert_eq!(
            m.tokens,
            Tokens {
                input: 10,
                output: 4,
                cache_create: 30,
                cache_read: 50,
                cache_write_5m: 10,
                cache_write_1h: 20,
                web_search_requests: 2,
            }
        );
        assert_eq!(m.usage_str("inference_geo"), Some("us"));
        assert_eq!(m.tokens.prompt(), 90);
        assert_eq!(m.tokens.total(), 94);
    }

    #[test]
    fn cache_writes_without_breakdown_count_as_5m() {
        let mut s = Sniffer::new("application/json");
        s.feed(&Bytes::from(
            json!({"model": "m", "usage": {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 7}})
                .to_string(),
        ));
        let t = s.finalize().unwrap().tokens;
        assert_eq!(
            (t.cache_create, t.cache_write_5m, t.cache_write_1h),
            (7, 7, 0)
        );
    }

    #[test]
    fn stream_keeps_start_counts_when_delta_zeroes_them() {
        let mut s = Sniffer::new("text/event-stream");
        s.feed(&sse(&[
            ("message_start", json!({"message": {"model": "m", "usage": {
                "input_tokens": 100, "output_tokens": 1, "cache_read_input_tokens": 40,
                "cache_creation_input_tokens": 0, "speed": "fast"}}})),
            ("message_delta", json!({"usage": {"input_tokens": 0, "output_tokens": 25,
                "cache_read_input_tokens": 0, "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}}})),
            ("message_stop", json!({})),
        ]));
        let m = s.finalize().unwrap();
        assert_eq!(
            (m.tokens.input, m.tokens.output, m.tokens.cache_read),
            (100, 25, 40)
        );
        assert_eq!(m.usage_str("speed"), Some("fast"));
    }

    #[test]
    fn stream_takes_full_delta_usage() {
        let mut s = Sniffer::new("text/event-stream");
        s.feed(&sse(&[
            ("message_start", json!({"message": {"model": "m", "usage": {"input_tokens": 5, "output_tokens": 1}}})),
            ("message_delta", json!({"usage": {"input_tokens": 5, "output_tokens": 9,
                "server_tool_use": {"web_search_requests": 1}}})),
        ]));
        let t = s.finalize().unwrap().tokens;
        assert_eq!((t.input, t.output, t.web_search_requests), (5, 9, 1));
    }

    #[test]
    fn stream_split_across_chunks() {
        let all = sse(&[
            (
                "message_start",
                json!({"message": {"model": "m", "usage": {"input_tokens": 3, "output_tokens": 1}}}),
            ),
            ("message_delta", json!({"usage": {"output_tokens": 8}})),
        ]);
        let mut s = Sniffer::new("text/event-stream");
        for c in all.chunks(5) {
            s.feed(&Bytes::copy_from_slice(c));
        }
        let t = s.finalize().unwrap().tokens;
        assert_eq!((t.input, t.output), (3, 8));
    }

    #[test]
    fn stream_cut_before_message_delta_counts_deltas() {
        let mut s = Sniffer::new("text/event-stream");
        s.feed(&sse(&[
            ("message_start", json!({"message": {"model": "m", "usage": {"input_tokens": 12, "output_tokens": 1}}})),
            ("content_block_delta", json!({"delta": {"text": "a"}})),
            ("content_block_delta", json!({"delta": {"text": "b"}})),
            ("content_block_delta", json!({"delta": {"text": "c"}})),
        ]));
        let m = s.finalize().unwrap();
        assert!(m.partial);
        assert_eq!((m.tokens.input, m.tokens.output), (12, 3));
    }

    #[test]
    fn complete_stream_is_not_partial_and_uses_reported_output() {
        let mut s = Sniffer::new("text/event-stream");
        s.feed(&sse(&[
            ("message_start", json!({"message": {"model": "m", "usage": {"input_tokens": 1, "output_tokens": 1}}})),
            ("content_block_delta", json!({"delta": {"text": "a"}})),
            ("content_block_delta", json!({"delta": {"text": "b"}})),
            ("message_delta", json!({"usage": {"output_tokens": 1}})),
        ]));
        let m = s.finalize().unwrap();
        assert!(!m.partial);
        assert_eq!(m.tokens.output, 1);
    }

    #[test]
    fn empty_stream_records_nothing() {
        let mut s = Sniffer::new("text/event-stream");
        s.feed(&sse(&[("ping", json!({}))]));
        assert!(s.finalize().is_none());
    }
}
