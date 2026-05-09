use std::collections::BTreeMap;

use bytes::Bytes;

#[derive(Debug, Default, Clone, Copy)]
pub struct Tokens {
    pub input: u64,
    pub output: u64,
    pub cache_create: u64,
    pub cache_read: u64,
}

impl Tokens {
    pub fn add(&mut self, other: &Tokens) {
        self.input += other.input;
        self.output += other.output;
        self.cache_create += other.cache_create;
        self.cache_read += other.cache_read;
    }
}

#[derive(Debug, Default)]
pub struct Totals {
    pub by_model: BTreeMap<String, Tokens>,
    pub grand: Tokens,
    pub requests: u64,
}

impl Totals {
    pub fn record(&mut self, model: &str, t: &Tokens) -> Tokens {
        self.by_model.entry(model.to_string()).or_default().add(t);
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
            "  {:<32} {:>10} {:>10} {:>14} {:>12}",
            "model", "input", "output", "cache_create", "cache_read"
        );
        for (model, t) in &self.by_model {
            println!(
                "  {:<32} {:>10} {:>10} {:>14} {:>12}",
                model, t.input, t.output, t.cache_create, t.cache_read
            );
        }
        println!(
            "  {:<32} {:>10} {:>10} {:>14} {:>12}",
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
    tokens: Tokens,
    saw_delta: bool,
}

impl Sniffer {
    pub fn new(content_type: &str) -> Self {
        let is_sse = content_type.contains("text/event-stream");
        Self {
            is_sse,
            leftover: Vec::new(),
            json_buf: Vec::new(),
            model: None,
            tokens: Tokens::default(),
            saw_delta: false,
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

    pub fn finalize(mut self) -> Option<(String, Tokens)> {
        if !self.is_sse {
            let v: serde_json::Value = serde_json::from_slice(&self.json_buf).ok()?;
            let model = v.get("model")?.as_str()?.to_string();
            let u = v.get("usage")?;
            let t = read_usage(u);
            return Some((model, t));
        }
        if !self.saw_delta && self.tokens.output == 0 {
            // Allow message_start usage as a fallback; it sets output=1.
        }
        let model = self.model.take().unwrap_or_else(|| "unknown".into());
        Some((model, self.tokens))
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
        let json: serde_json::Value = match serde_json::from_str(data) {
            Ok(v) => v,
            Err(_) => return,
        };
        match event {
            "message_start" => {
                if let Some(m) = json.pointer("/message/model").and_then(|v| v.as_str()) {
                    self.model = Some(m.to_string());
                }
                if let Some(u) = json.pointer("/message/usage") {
                    let t = read_usage(u);
                    self.tokens = t;
                }
            }
            "message_delta" => {
                if let Some(u) = json.pointer("/usage") {
                    let t = read_usage(u);
                    if t.input > 0 {
                        self.tokens.input = t.input;
                    }
                    if t.cache_create > 0 {
                        self.tokens.cache_create = t.cache_create;
                    }
                    if t.cache_read > 0 {
                        self.tokens.cache_read = t.cache_read;
                    }
                    self.tokens.output = t.output;
                    self.saw_delta = true;
                }
            }
            _ => {}
        }
    }
}

fn read_usage(v: &serde_json::Value) -> Tokens {
    Tokens {
        input: v.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
        output: v.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0),
        cache_create: v
            .get("cache_creation_input_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
        cache_read: v
            .get("cache_read_input_tokens")
            .and_then(|x| x.as_u64())
            .unwrap_or(0),
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
