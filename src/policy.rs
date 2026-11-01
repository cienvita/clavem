//! Access policies, stored as JSONB on tenants and keys and carried in
//! tokens.
//!
//! A request must pass every layer: the tenant policy, then the key
//! policy, then the token policy if there is one. Lower layers can only
//! narrow. An absent field means "no restriction at this layer", except
//! that the tenant layer falls back to [`DEFAULT_PATHS`] when it lists no
//! paths, so a new tenant reaches the Messages API and nothing else.
//!
//! Patterns are exact strings, or a prefix ending in `*`. A lone `*`
//! matches everything.

use serde::{Deserialize, Serialize};

/// Paths a tenant may call when its policy names none. Excludes Managed
/// Agents (`v1/agents`, `v1/sessions`, ...), batches and files, whose
/// usage clavem cannot meter from the response.
pub const DEFAULT_PATHS: &[&str] = &[
    "v1/messages",
    "v1/messages/count_tokens",
    "v1/models",
    "v1/models/*",
];

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Provider names (path prefixes) this layer allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<String>>,
    /// Upstream paths, without the provider prefix or leading slash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    /// Model ids, checked against the request body's `model`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
    /// Ceiling on the request body's `max_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
}

/// What a policy is checked against.
pub struct Request<'a> {
    pub provider: &'a str,
    pub path: &'a str,
    pub model: Option<&'a str>,
    pub max_tokens: Option<u64>,
}

#[derive(Debug, PartialEq)]
pub struct Denied(pub String);

#[derive(Clone, Copy, PartialEq)]
pub enum Layer {
    Tenant,
    Key,
    Token,
}

impl Layer {
    fn name(self) -> &'static str {
        match self {
            Layer::Tenant => "tenant",
            Layer::Key => "key",
            Layer::Token => "token",
        }
    }
}

impl Policy {
    pub fn validate(&self) -> Result<(), String> {
        for (field, list) in [
            ("providers", &self.providers),
            ("paths", &self.paths),
            ("models", &self.models),
        ] {
            if let Some(list) = list {
                for p in list {
                    if p.is_empty() {
                        return Err(format!("{field}: empty pattern"));
                    }
                    if p.find('*').is_some_and(|i| i != p.len() - 1) {
                        return Err(format!("{field}: '*' is only allowed at the end: {p:?}"));
                    }
                }
            }
        }
        if let Some(paths) = &self.paths {
            for p in paths {
                if p.starts_with('/') {
                    return Err(format!("paths: no leading '/': {p:?}"));
                }
            }
        }
        Ok(())
    }

    pub fn check(&self, layer: Layer, req: &Request) -> Result<(), Denied> {
        let who = layer.name();
        if let Some(list) = &self.providers
            && !any_match(list, req.provider)
        {
            return Err(Denied(format!(
                "{who} policy does not allow provider {:?}",
                req.provider
            )));
        }
        let path_ok = match &self.paths {
            Some(list) => any_match(list, req.path),
            None if layer == Layer::Tenant => {
                DEFAULT_PATHS.iter().any(|p| pattern_match(p, req.path))
            }
            None => true,
        };
        if !path_ok {
            return Err(Denied(format!(
                "{who} policy does not allow path {:?}",
                req.path
            )));
        }
        if let (Some(list), Some(model)) = (&self.models, req.model)
            && !any_match(list, model)
        {
            return Err(Denied(format!(
                "{who} policy does not allow model {model:?}"
            )));
        }
        if let (Some(cap), Some(asked)) = (self.max_tokens, req.max_tokens)
            && asked > cap
        {
            return Err(Denied(format!(
                "{who} policy caps max_tokens at {cap}, request asked for {asked}"
            )));
        }
        Ok(())
    }

    /// Whether checking this policy needs the request body parsed.
    pub fn needs_body(&self) -> bool {
        self.models.is_some() || self.max_tokens.is_some()
    }
}

fn any_match<S: AsRef<str>>(list: &[S], value: &str) -> bool {
    list.iter().any(|p| pattern_match(p.as_ref(), value))
}

pub fn pattern_match(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

/// Rejects paths that an HTTP client or upstream server might normalise
/// into a different path than the one the policy saw: dot segments,
/// encoded slashes and backslashes, empty segments.
pub fn path_is_canonical(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    path.split('/').all(|seg| {
        let lower = seg.to_ascii_lowercase();
        let decoded_dots = lower.replace("%2e", ".");
        !seg.is_empty()
            && decoded_dots != "."
            && decoded_dots != ".."
            && !lower.contains("%2f")
            && !lower.contains("%5c")
            && !seg.contains('\\')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(path: &'a str, model: Option<&'a str>, max_tokens: Option<u64>) -> Request<'a> {
        Request {
            provider: "anthropic",
            path,
            model,
            max_tokens,
        }
    }

    #[test]
    fn empty_tenant_policy_allows_messages_only() {
        let p = Policy::default();
        assert!(
            p.check(Layer::Tenant, &req("v1/messages", Some("x"), Some(10)))
                .is_ok()
        );
        assert!(
            p.check(
                Layer::Tenant,
                &req("v1/models/claude-haiku-5-5", None, None)
            )
            .is_ok()
        );
        assert!(
            p.check(Layer::Tenant, &req("v1/sessions", None, None))
                .is_err()
        );
        assert!(
            p.check(Layer::Tenant, &req("v1/agents", None, None))
                .is_err()
        );
        assert!(
            p.check(Layer::Tenant, &req("v1/messages/batches", None, None))
                .is_err()
        );
    }

    #[test]
    fn empty_key_policy_adds_no_restriction() {
        let p = Policy::default();
        assert!(p.check(Layer::Key, &req("v1/sessions", None, None)).is_ok());
    }

    #[test]
    fn explicit_paths_replace_defaults() {
        let p: Policy = serde_json::from_value(serde_json::json!({"paths": ["v1/*"]})).unwrap();
        assert!(
            p.check(Layer::Tenant, &req("v1/sessions", None, None))
                .is_ok()
        );
        assert!(p.check(Layer::Tenant, &req("v2/x", None, None)).is_err());
    }

    #[test]
    fn models_and_max_tokens() {
        let p: Policy = serde_json::from_value(serde_json::json!({
            "models": ["claude-haiku-*"], "max_tokens": 100
        }))
        .unwrap();
        assert!(
            p.check(
                Layer::Key,
                &req("v1/messages", Some("claude-haiku-5-5"), Some(100))
            )
            .is_ok()
        );
        let e = p
            .check(
                Layer::Key,
                &req("v1/messages", Some("claude-opus-5-5"), None),
            )
            .unwrap_err();
        assert!(e.0.contains("key policy does not allow model"), "{}", e.0);
        let e = p
            .check(
                Layer::Key,
                &req("v1/messages", Some("claude-haiku-5-5"), Some(101)),
            )
            .unwrap_err();
        assert!(e.0.contains("caps max_tokens at 100"), "{}", e.0);
        // A request with no model (GET v1/models) is not refused for it.
        assert!(p.check(Layer::Key, &req("v1/models", None, None)).is_ok());
    }

    #[test]
    fn providers() {
        let p: Policy =
            serde_json::from_value(serde_json::json!({"providers": ["anthropic"]})).unwrap();
        assert!(p.check(Layer::Key, &req("v1/messages", None, None)).is_ok());
        let r = Request {
            provider: "xai",
            path: "v1/messages",
            model: None,
            max_tokens: None,
        };
        assert!(p.check(Layer::Key, &r).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let r: Result<Policy, _> = serde_json::from_value(serde_json::json!({"model": ["x"]}));
        assert!(r.is_err());
    }

    #[test]
    fn validate_rejects_bad_patterns() {
        for bad in [
            serde_json::json!({"models": ["clau*de"]}),
            serde_json::json!({"paths": ["/v1/messages"]}),
            serde_json::json!({"providers": [""]}),
        ] {
            let p: Policy = serde_json::from_value(bad.clone()).unwrap();
            assert!(p.validate().is_err(), "{bad}");
        }
        let ok: Policy = serde_json::from_value(serde_json::json!({"models": ["*"]})).unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn non_canonical_paths_are_refused() {
        for bad in [
            "v1/models/../agents",
            "v1/models/%2e%2e/agents",
            "v1/models/.%2E/agents",
            "v1/models/./x",
            "v1/models%2fagents",
            "v1/models%5Cagents",
            "v1//messages",
            "v1/messages/",
            "v1\\messages",
        ] {
            assert!(!path_is_canonical(bad), "{bad}");
        }
        for good in [
            "",
            "v1/messages",
            "v1/models/claude-haiku-5-5",
            "v1/messages/count_tokens",
        ] {
            assert!(path_is_canonical(good), "{good}");
        }
    }
}
