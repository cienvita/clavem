use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::provider::Kind;

const DEFAULT_LISTEN: &str = "127.0.0.1:4567";
const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:4569";
pub const DEFAULT_CREDENTIAL: &str = "default";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    /// One entry per `[[provider]]` block.
    #[serde(default, rename = "provider")]
    pub providers: Vec<ProviderConfig>,
    /// Without a database clavem runs open: no client authentication, no
    /// budgets, usage only in memory. With one, `[auth]` is required.
    pub database: Option<DatabaseConfig>,
    pub auth: Option<AuthConfig>,
    pub admin: Option<AdminConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    /// libpq-style connection string or URL, without the password. Several
    /// hosts plus `target_session_attrs=read-write` follow the leader.
    pub url: String,
    pub password_file: Option<PathBuf>,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Secret for HMAC-hashing virtual key secrets, at least 32 bytes.
    pub pepper_file: PathBuf,
    /// Secret for signing access tokens, at least 32 bytes. Must differ
    /// from the pepper.
    pub token_key_file: PathBuf,
    #[serde(default = "default_token_max_ttl")]
    pub token_max_ttl_secs: u64,
    /// How long a resolved key, its tenant, grants and budgets are cached.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default = "default_admin_listen")]
    pub listen: SocketAddr,
    /// Bearer token for the management API.
    pub token_file: PathBuf,
}

/// One upstream credential of a provider. Several tenants can share one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub name: String,
    pub key_file: PathBuf,
}

fn default_pool_size() -> usize {
    16
}

fn default_token_max_ttl() -> u64 {
    3600
}

fn default_cache_ttl() -> u64 {
    30
}

fn default_admin_listen() -> SocketAddr {
    DEFAULT_ADMIN_LISTEN
        .parse()
        .expect("valid default admin address")
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
}

/// A provider instance: the same kind can appear several times under
/// different names (two Anthropic orgs, one Azure resource per region).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    /// Path prefix clients use, e.g. `anthropic` for `/anthropic/v1/messages`.
    pub name: String,
    pub kind: Kind,
    pub base_url: String,
    /// Shorthand for a single credential named `default`.
    pub key_file: Option<PathBuf>,
    #[serde(default, rename = "credential")]
    pub credentials: Vec<CredentialConfig>,
}

impl ProviderConfig {
    /// `key_file`, if given, as the `default` credential, then the
    /// `[[provider.credential]]` entries.
    pub fn all_credentials(&self) -> Vec<(String, PathBuf)> {
        let mut out = Vec::new();
        if let Some(k) = &self.key_file {
            out.push((DEFAULT_CREDENTIAL.to_string(), k.clone()));
        }
        for c in &self.credentials {
            out.push((c.name.clone(), c.key_file.clone()));
        }
        out
    }
}

impl Default for Server {
    fn default() -> Self {
        Self {
            listen: default_listen(),
        }
    }
}

fn default_listen() -> SocketAddr {
    DEFAULT_LISTEN
        .parse()
        .expect("valid default listen address")
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        Config::parse(&text).with_context(|| format!("parsing config {}", path.display()))
    }

    pub fn parse(text: &str) -> Result<Config> {
        let mut config: Config = toml::from_str(text)?;
        config.validate()?;
        for p in &mut config.providers {
            p.base_url = p.base_url.trim_end_matches('/').to_string();
            p.key_file = p.key_file.as_deref().map(expand_tilde);
            for c in &mut p.credentials {
                c.key_file = expand_tilde(&c.key_file);
            }
        }
        if let Some(d) = &mut config.database {
            d.password_file = d.password_file.as_deref().map(expand_tilde);
        }
        if let Some(a) = &mut config.auth {
            a.pepper_file = expand_tilde(&a.pepper_file);
            a.token_key_file = expand_tilde(&a.token_key_file);
        }
        if let Some(a) = &mut config.admin {
            a.token_file = expand_tilde(&a.token_file);
        }
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.providers.is_empty() {
            bail!("no providers configured; add at least one [[provider]] block");
        }
        let mut seen = HashSet::new();
        for p in &self.providers {
            if !is_path_segment(&p.name) {
                bail!(
                    "provider name {:?} must be non-empty and contain only \
                     letters, digits, '-' and '_'",
                    p.name
                );
            }
            if !seen.insert(p.name.as_str()) {
                bail!("duplicate provider name {:?}", p.name);
            }
            if p.name.starts_with('_') {
                bail!(
                    "provider name {:?}: a leading '_' is reserved for clavem",
                    p.name
                );
            }
            if !p.base_url.starts_with("http://") && !p.base_url.starts_with("https://") {
                bail!(
                    "provider {:?}: base_url must start with http:// or https://, got {:?}",
                    p.name,
                    p.base_url
                );
            }
            let creds = p.all_credentials();
            if creds.is_empty() {
                bail!(
                    "provider {:?}: needs key_file or at least one [[provider.credential]]",
                    p.name
                );
            }
            let mut seen_cred = HashSet::new();
            for (name, _) in &creds {
                if !is_path_segment(name) {
                    bail!(
                        "provider {:?}: credential name {name:?} must be letters, digits, '-' and '_'",
                        p.name
                    );
                }
                if !seen_cred.insert(name.as_str()) {
                    bail!("provider {:?}: duplicate credential {name:?}", p.name);
                }
            }
        }
        if self.database.is_some() && self.auth.is_none() {
            bail!("[database] requires an [auth] section");
        }
        if self.database.is_none() && (self.auth.is_some() || self.admin.is_some()) {
            bail!("[auth] and [admin] require a [database] section");
        }
        if let Some(a) = &self.auth {
            if a.token_max_ttl_secs == 0 {
                bail!("auth.token_max_ttl_secs must be positive");
            }
            if a.pepper_file == a.token_key_file {
                bail!("auth.pepper_file and auth.token_key_file must be different files");
            }
        }
        if let Some(d) = &self.database
            && d.pool_size == 0
        {
            bail!("database.pool_size must be positive");
        }
        if let Some(a) = &self.admin
            && a.listen == self.server.listen
        {
            bail!("admin.listen must differ from server.listen");
        }
        Ok(())
    }
}

fn is_path_segment(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub fn expand_tilde(p: &Path) -> PathBuf {
    let Some(s) = p.to_str() else {
        return p.to_path_buf();
    };
    let Some(rest) = s.strip_prefix("~/").or_else(|| s.strip_prefix("~\\")) else {
        return p.to_path_buf();
    };
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    match home {
        Some(h) => h.join(rest),
        None => p.to_path_buf(),
    }
}

pub fn read_key_file(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path)?;
    let key = text.trim();
    if key.is_empty() {
        bail!("key file is empty");
    }
    Ok(key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        [server]
        listen = "0.0.0.0:8080"

        [[provider]]
        name = "anthropic"
        kind = "anthropic"
        base_url = "https://api.anthropic.com/"
        key_file = "/keys/anthropic.key"

        [[provider]]
        name = "azure-eu"
        kind = "azure"
        base_url = "https://eu.openai.azure.com"
        key_file = "/keys/azure-eu.key"
    "#;

    #[test]
    fn parses_providers_and_listen() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.server.listen.to_string(), "0.0.0.0:8080");
        assert_eq!(c.providers.len(), 2);
        assert_eq!(c.providers[0].kind, Kind::Anthropic);
        // Trailing slash is dropped so joining a rest path cannot double up.
        assert_eq!(c.providers[0].base_url, "https://api.anthropic.com");
        assert_eq!(c.providers[1].kind, Kind::Azure);
    }

    #[test]
    fn listen_defaults_when_server_section_absent() {
        let c = Config::parse(
            r#"
            [[provider]]
            name = "xai"
            kind = "xai"
            base_url = "https://api.x.ai"
            key_file = "/keys/xai.key"
        "#,
        )
        .unwrap();
        assert_eq!(c.server.listen.to_string(), DEFAULT_LISTEN);
    }

    #[test]
    fn rejects_empty_config() {
        let err = Config::parse("").unwrap_err().to_string();
        assert!(err.contains("no providers"), "{err}");
    }

    #[test]
    fn rejects_duplicate_names() {
        let text = format!(
            "{SAMPLE}\n{}",
            &SAMPLE[SAMPLE.find("[[provider]]").unwrap()..]
        );
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("duplicate provider name"), "{err}");
    }

    #[test]
    fn rejects_name_with_slash() {
        let err = Config::parse(&SAMPLE.replace("name = \"anthropic\"", "name = \"an/thropic\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be non-empty"), "{err}");
    }

    #[test]
    fn rejects_base_url_without_scheme() {
        let err = Config::parse(&SAMPLE.replace("https://api.anthropic.com/", "api.anthropic.com"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("http://"), "{err}");
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = Config::parse(&SAMPLE.replace("kind = \"azure\"", "kind = \"openai\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("openai"), "{err}");
    }

    const DB: &str = r#"
        [database]
        url = "host=127.0.0.1 port=55432 user=clavem dbname=clavem"

        [auth]
        pepper_file = "/keys/pepper"
        token_key_file = "/keys/token"

        [admin]
        token_file = "/keys/admin"
    "#;

    #[test]
    fn key_file_is_the_default_credential_and_more_can_be_added() {
        let c = Config::parse(&SAMPLE.replace(
            "key_file = \"/keys/anthropic.key\"",
            "key_file = \"/keys/anthropic.key\"\n[[provider.credential]]\nname = \"research\"\nkey_file = \"/keys/r.key\"",
        ))
        .unwrap();
        let names: Vec<_> = c.providers[0]
            .all_credentials()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["default", "research"]);
    }

    #[test]
    fn credentials_only_is_fine() {
        let c = Config::parse(
            r#"
            [[provider]]
            name = "anthropic"
            kind = "anthropic"
            base_url = "https://api.anthropic.com"
            [[provider.credential]]
            name = "a"
            key_file = "/k/a"
            [[provider.credential]]
            name = "b"
            key_file = "/k/b"
        "#,
        )
        .unwrap();
        assert_eq!(c.providers[0].all_credentials().len(), 2);
    }

    #[test]
    fn rejects_provider_without_credentials() {
        let err = Config::parse(&SAMPLE.replace("key_file = \"/keys/azure-eu.key\"", ""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("needs key_file"), "{err}");
    }

    #[test]
    fn rejects_duplicate_credential() {
        let err = Config::parse(&SAMPLE.replace(
            "key_file = \"/keys/anthropic.key\"",
            "key_file = \"/keys/anthropic.key\"\n[[provider.credential]]\nname = \"default\"\nkey_file = \"/k\"",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("duplicate credential"), "{err}");
    }

    #[test]
    fn rejects_reserved_provider_name() {
        let err = Config::parse(&SAMPLE.replace("name = \"anthropic\"", "name = \"_clavem\""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "{err}");
    }

    #[test]
    fn parses_database_auth_admin() {
        let c = Config::parse(&format!("{SAMPLE}{DB}")).unwrap();
        assert_eq!(c.database.as_ref().unwrap().pool_size, 16);
        let a = c.auth.as_ref().unwrap();
        assert_eq!((a.token_max_ttl_secs, a.cache_ttl_secs), (3600, 30));
        assert_eq!(
            c.admin.as_ref().unwrap().listen.to_string(),
            DEFAULT_ADMIN_LISTEN
        );
    }

    #[test]
    fn database_requires_auth() {
        let err = Config::parse(&format!("{SAMPLE}{}", &DB[..DB.find("[auth]").unwrap()]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("requires an [auth]"), "{err}");
    }

    #[test]
    fn auth_requires_database() {
        let err = Config::parse(&format!("{SAMPLE}{}", &DB[DB.find("[auth]").unwrap()..]))
            .unwrap_err()
            .to_string();
        assert!(err.contains("require a [database]"), "{err}");
    }

    #[test]
    fn pepper_and_token_key_must_differ() {
        let err = Config::parse(&format!(
            "{SAMPLE}{}",
            DB.replace("/keys/token", "/keys/pepper")
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be different"), "{err}");
    }

    #[test]
    fn rejects_unknown_field() {
        let err = Config::parse(&format!("{SAMPLE}\nregion = \"eu\"\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{err}");
    }
}
