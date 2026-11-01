use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::Deserialize;

use crate::config::{Config, DEFAULT_CREDENTIAL, read_key_file};

const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Wire dialect of a provider. Decides which header carries the upstream
/// credential, and (later) which usage sniffer applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Anthropic,
    Xai,
    Azure,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Anthropic => "anthropic",
            Kind::Xai => "xai",
            Kind::Azure => "azure",
        }
    }
}

/// Headers we never forward: the client's own credential slots (we
/// substitute the real one) and hop-by-hop / length headers that reqwest
/// recomputes for the upstream request.
const DROP_REQUEST_HEADERS: &[&str] = &[
    "host",
    "x-api-key",
    "authorization",
    "api-key",
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    // We hand the body straight back to the client, so let the upstream
    // send it uncompressed rather than decoding and re-encoding.
    "accept-encoding",
];

/// Response headers reqwest/hyper own for the downstream connection.
const DROP_RESPONSE_HEADERS: &[&str] = &[
    "connection",
    "content-length",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
];

pub struct Provider {
    pub name: String,
    pub kind: Kind,
    /// Upstream root, no trailing slash.
    pub base_url: String,
    /// Credential name -> header value, built once at startup. Ordered so
    /// the open (no database) mode picks a stable first credential.
    credentials: BTreeMap<String, HeaderValue>,
}

impl Provider {
    /// A provider with one credential named `default`.
    pub fn new(
        name: impl Into<String>,
        kind: Kind,
        base_url: impl Into<String>,
        api_key: &str,
    ) -> Result<Provider> {
        Provider::with_credentials(name, kind, base_url, [(DEFAULT_CREDENTIAL, api_key)])
    }

    /// Fails if a credential cannot be a header value, so a mangled key
    /// file is a startup error rather than a puzzling 401 later.
    pub fn with_credentials<'a>(
        name: impl Into<String>,
        kind: Kind,
        base_url: impl Into<String>,
        creds: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Provider> {
        let name = name.into();
        let mut credentials = BTreeMap::new();
        for (cred, api_key) in creds {
            let raw = match kind {
                Kind::Anthropic | Kind::Azure => api_key.to_string(),
                Kind::Xai => format!("Bearer {api_key}"),
            };
            let mut value = HeaderValue::from_str(&raw).with_context(|| {
                format!(
                    "provider {name:?} credential {cred:?}: api key is not a valid header value"
                )
            })?;
            value.set_sensitive(true);
            credentials.insert(cred.to_string(), value);
        }
        anyhow::ensure!(!credentials.is_empty(), "provider {name:?}: no credentials");
        Ok(Provider {
            name,
            kind,
            base_url: base_url.into().trim_end_matches('/').to_string(),
            credentials,
        })
    }

    fn auth_header(&self) -> HeaderName {
        HeaderName::from_static(match self.kind {
            Kind::Anthropic => "x-api-key",
            Kind::Xai => "authorization",
            Kind::Azure => "api-key",
        })
    }

    pub fn credential_names(&self) -> impl Iterator<Item = &str> {
        self.credentials.keys().map(String::as_str)
    }

    pub fn has_credential(&self, name: &str) -> bool {
        self.credentials.contains_key(name)
    }

    /// The credential used when no tenant grant picks one.
    pub fn first_credential(&self) -> &str {
        self.credentials
            .keys()
            .next()
            .expect("at least one credential")
    }

    /// Upstream URL for a rest path (no leading slash) and optional query.
    pub fn upstream_url(&self, rest: &str, query: Option<&str>) -> String {
        let mut url = format!("{}/{rest}", self.base_url);
        if let Some(q) = query {
            url.push('?');
            url.push_str(q);
        }
        url
    }

    /// Copies the client's headers, dropping the ones we must not forward,
    /// and injects the named upstream credential. Panics on an unknown
    /// credential; callers pick from [`Provider::credential_names`].
    pub fn upstream_headers_with(&self, from_client: &HeaderMap, credential: &str) -> HeaderMap {
        let mut headers = HeaderMap::with_capacity(from_client.len() + 2);
        for (name, value) in from_client {
            if DROP_REQUEST_HEADERS.contains(&name.as_str()) {
                continue;
            }
            headers.append(name.clone(), value.clone());
        }
        let value = self
            .credentials
            .get(credential)
            .unwrap_or_else(|| panic!("provider {:?} has no credential {credential:?}", self.name));
        headers.insert(self.auth_header(), value.clone());
        if self.kind == Kind::Anthropic && !headers.contains_key("anthropic-version") {
            headers.insert(
                "anthropic-version",
                HeaderValue::from_static(ANTHROPIC_VERSION),
            );
        }
        headers
    }
}

impl Provider {
    /// Headers for the first credential, as used in open mode.
    pub fn upstream_headers(&self, from_client: &HeaderMap) -> HeaderMap {
        self.upstream_headers_with(from_client, self.first_credential())
    }
}

/// Hand-written so the credential cannot reach a log line.
impl std::fmt::Debug for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provider")
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("base_url", &self.base_url)
            .field("credentials", &self.credentials.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

pub fn strip_response_headers(headers: &mut HeaderMap) {
    for name in DROP_RESPONSE_HEADERS {
        headers.remove(*name);
    }
}

/// Provider instances keyed by the path prefix that selects them.
pub struct Registry {
    by_name: BTreeMap<String, Arc<Provider>>,
}

impl Registry {
    pub fn new(providers: Vec<Provider>) -> Registry {
        Registry {
            by_name: providers
                .into_iter()
                .map(|p| (p.name.clone(), Arc::new(p)))
                .collect(),
        }
    }

    /// Builds the registry, reading each provider's credential from disk.
    pub fn from_config(config: &Config) -> Result<Registry> {
        let mut providers = Vec::with_capacity(config.providers.len());
        for p in &config.providers {
            let mut keys = Vec::new();
            for (cred, path) in p.all_credentials() {
                let key = read_key_file(&path).with_context(|| {
                    format!(
                        "provider {:?} credential {cred:?}: reading key from {}",
                        p.name,
                        path.display()
                    )
                })?;
                keys.push((cred, key));
            }
            providers.push(Provider::with_credentials(
                &p.name,
                p.kind,
                &p.base_url,
                keys.iter().map(|(c, k)| (c.as_str(), k.as_str())),
            )?);
        }
        Ok(Registry::new(providers))
    }

    pub fn get(&self, name: &str) -> Option<&Arc<Provider>> {
        self.by_name.get(name)
    }

    pub fn providers(&self) -> impl Iterator<Item = &Arc<Provider>> {
        self.by_name.values()
    }

    /// Splits `/{name}/{rest}` into the provider and the rest path, which
    /// is forwarded verbatim. `/{name}` alone yields an empty rest.
    pub fn route(&self, path: &str) -> Option<(Arc<Provider>, String)> {
        let trimmed = path.trim_start_matches('/');
        let (name, rest) = match trimmed.split_once('/') {
            Some((name, rest)) => (name, rest),
            None => (trimmed, ""),
        };
        let provider = self.by_name.get(name)?;
        Some((provider.clone(), rest.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry::new(vec![
            Provider::new(
                "anthropic",
                Kind::Anthropic,
                "https://api.anthropic.com",
                "sk-ant-real",
            )
            .unwrap(),
            Provider::new("xai", Kind::Xai, "https://api.x.ai", "xai-real").unwrap(),
            Provider::new(
                "azure-eu",
                Kind::Azure,
                "https://eu.openai.azure.com/",
                "azure-real",
            )
            .unwrap(),
        ])
    }

    fn header_value(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).unwrap()
    }

    fn get(headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get(name)
            .map(|v| v.to_str().unwrap_or_default().to_string())
    }

    #[test]
    fn rejects_a_key_that_cannot_be_a_header_value() {
        let err = Provider::new("anthropic", Kind::Anthropic, "https://x", "bad\nkey")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid header value"), "{err}");
    }

    #[test]
    fn routes_prefix_to_provider_and_rest() {
        let r = registry();
        let (p, rest) = r.route("/anthropic/v1/messages").unwrap();
        assert_eq!(p.name, "anthropic");
        assert_eq!(rest, "v1/messages");
        assert_eq!(
            p.upstream_url(&rest, Some("beta=true")),
            "https://api.anthropic.com/v1/messages?beta=true"
        );
    }

    #[test]
    fn routes_bare_prefix_to_empty_rest() {
        let r = registry();
        let (p, rest) = r.route("/xai").unwrap();
        assert_eq!(p.name, "xai");
        assert_eq!(rest, "");
        assert_eq!(p.upstream_url(&rest, None), "https://api.x.ai/");
    }

    #[test]
    fn unknown_prefix_does_not_route() {
        assert!(registry().route("/openai/v1/chat/completions").is_none());
        assert!(registry().route("/").is_none());
    }

    #[test]
    fn anthropic_swaps_key_and_defaults_version() {
        let mut client = HeaderMap::new();
        client.insert("x-api-key", header_value("client-placeholder"));
        client.insert("content-type", header_value("application/json"));
        client.insert("host", header_value("127.0.0.1:4567"));

        let (p, _) = registry().route("/anthropic/v1/messages").unwrap();
        let out = p.upstream_headers(&client);
        assert_eq!(get(&out, "x-api-key").as_deref(), Some("sk-ant-real"));
        assert_eq!(
            get(&out, "anthropic-version").as_deref(),
            Some("2023-06-01")
        );
        assert_eq!(
            get(&out, "content-type").as_deref(),
            Some("application/json")
        );
        assert!(out.get("host").is_none());
    }

    #[test]
    fn anthropic_keeps_client_supplied_version() {
        let mut client = HeaderMap::new();
        client.insert("anthropic-version", header_value("2024-10-22"));
        let (p, _) = registry().route("/anthropic").unwrap();
        let out = p.upstream_headers(&client);
        assert_eq!(
            get(&out, "anthropic-version").as_deref(),
            Some("2024-10-22")
        );
    }

    #[test]
    fn xai_gets_bearer_and_azure_gets_api_key() {
        let mut client = HeaderMap::new();
        client.insert("authorization", header_value("Bearer client-placeholder"));

        let (xai, _) = registry().route("/xai/v1/chat/completions").unwrap();
        let out = xai.upstream_headers(&client);
        assert_eq!(
            get(&out, "authorization").as_deref(),
            Some("Bearer xai-real")
        );

        let (azure, _) = registry().route("/azure-eu/openai/deployments/x").unwrap();
        let out = azure.upstream_headers(&client);
        assert_eq!(get(&out, "api-key").as_deref(), Some("azure-real"));
        // The client's placeholder bearer must not reach Azure.
        assert!(out.get("authorization").is_none());
    }
}
