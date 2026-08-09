use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::provider::Kind;

const DEFAULT_LISTEN: &str = "127.0.0.1:4567";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: Server,
    /// One entry per `[[provider]]` block.
    #[serde(default, rename = "provider")]
    pub providers: Vec<ProviderConfig>,
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
    pub key_file: PathBuf,
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
            p.key_file = expand_tilde(&p.key_file);
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
            if !p.base_url.starts_with("http://") && !p.base_url.starts_with("https://") {
                bail!(
                    "provider {:?}: base_url must start with http:// or https://, got {:?}",
                    p.name,
                    p.base_url
                );
            }
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

    #[test]
    fn rejects_unknown_field() {
        let err = Config::parse(&format!("{SAMPLE}\nregion = \"eu\"\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{err}");
    }
}
