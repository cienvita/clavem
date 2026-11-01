//! Virtual keys and short-lived access tokens.
//!
//! A virtual key is `clv_<id>_<secret>_<check>`:
//!
//! * `id`: 12 lowercase base32 chars, public. Primary key of the row and
//!   what logs show.
//! * `secret`: 32 random bytes, base64url without padding. Only
//!   HMAC-SHA256(pepper, secret) is stored.
//! * `check`: CRC32 of everything before it, 8 hex chars. Lets secret
//!   scanners recognise a key and rejects typos without a database lookup.
//!   It is not a security control.
//!
//! The key carries no authority of its own; tenant, policy and expiry live
//! in the database. A token is the opposite: `clvt_<payload>.<sig>`, where
//! the payload is base64url JSON naming the key, tenant, expiry and an
//! optional narrowing policy, signed with HMAC-SHA256 under a separate
//! token key. Tokens are minted by exchanging a key and cannot mint more.

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::policy::Policy;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_PREFIX: &str = "clv_";
pub const TOKEN_PREFIX: &str = "clvt_";
const ID_LEN: usize = 12;
const SECRET_BYTES: usize = 32;
const ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Server-side secret for hashing key secrets. At least 32 bytes.
#[derive(Clone)]
pub struct Pepper(Vec<u8>);

/// Server-side secret for signing tokens. At least 32 bytes.
#[derive(Clone)]
pub struct TokenKey(Vec<u8>);

impl Pepper {
    pub fn new(bytes: Vec<u8>) -> Result<Pepper> {
        check_secret_len("pepper", &bytes)?;
        Ok(Pepper(bytes))
    }

    pub fn hash(&self, secret: &str) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac takes any key length");
        mac.update(secret.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Constant-time comparison against a stored hash.
    pub fn verify(&self, secret: &str, stored: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac takes any key length");
        mac.update(secret.as_bytes());
        mac.verify_slice(stored).is_ok()
    }
}

impl TokenKey {
    pub fn new(bytes: Vec<u8>) -> Result<TokenKey> {
        check_secret_len("token key", &bytes)?;
        Ok(TokenKey(bytes))
    }

    fn mac(&self, data: &[u8]) -> HmacSha256 {
        let mut mac = HmacSha256::new_from_slice(&self.0).expect("hmac takes any key length");
        mac.update(data);
        mac
    }
}

fn check_secret_len(what: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() < 32 {
        bail!("{what} must be at least 32 bytes, got {}", bytes.len());
    }
    Ok(())
}

impl std::fmt::Debug for Pepper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pepper(..)")
    }
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenKey(..)")
    }
}

/// A freshly generated key. `full` is shown to the caller once.
pub struct NewKey {
    pub id: String,
    pub full: String,
    pub secret_hmac: [u8; 32],
    pub hint: String,
}

pub fn generate_key(pepper: &Pepper) -> Result<NewKey> {
    let mut idb = [0u8; ID_LEN];
    getrandom::fill(&mut idb).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let id: String = idb
        .iter()
        .map(|b| ID_ALPHABET[(*b as usize) % ID_ALPHABET.len()] as char)
        .collect();
    let mut sb = [0u8; SECRET_BYTES];
    getrandom::fill(&mut sb).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    let secret = URL_SAFE_NO_PAD.encode(sb);
    let body = format!("{KEY_PREFIX}{id}_{secret}");
    let full = format!("{body}_{:08x}", crc32fast::hash(body.as_bytes()));
    Ok(NewKey {
        secret_hmac: pepper.hash(&secret),
        hint: full[full.len() - 4..].to_string(),
        id,
        full,
    })
}

/// A key string split into its parts, checksum verified.
#[derive(Debug, PartialEq)]
pub struct ParsedKey<'a> {
    pub id: &'a str,
    pub secret: &'a str,
}

pub fn parse_key(s: &str) -> Option<ParsedKey<'_>> {
    let rest = s.strip_prefix(KEY_PREFIX)?;
    // The secret is base64url, which may itself contain '_', so split the
    // id off the front and the checksum off the back.
    if rest.len() < ID_LEN + 1 + 1 + 1 + 8 {
        return None;
    }
    let (id, rest) = rest.split_at(ID_LEN);
    let rest = rest.strip_prefix('_')?;
    let (secret, check) = rest.rsplit_once('_')?;
    if !id.bytes().all(|b| ID_ALPHABET.contains(&b))
        || secret.is_empty()
        || check.len() != 8
        || !check
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    let body = &s[..s.len() - 9];
    if format!("{:08x}", crc32fast::hash(body.as_bytes())) != check {
        return None;
    }
    Some(ParsedKey { id, secret })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenClaims {
    pub v: u8,
    /// Virtual key the token was minted from.
    pub kid: String,
    /// Tenant, checked against the key's current tenant on use.
    pub tid: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub jti: Uuid,
    /// Further narrowing on top of the tenant and key policies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pol: Option<Policy>,
}

pub fn sign_token(key: &TokenKey, claims: &TokenClaims) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims serialize"));
    let signed = format!("{TOKEN_PREFIX}{payload}");
    let sig = URL_SAFE_NO_PAD.encode(key.mac(signed.as_bytes()).finalize().into_bytes());
    format!("{signed}.{sig}")
}

#[derive(Debug, PartialEq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
}

/// Verifies signature and expiry. `now` is unix seconds.
pub fn verify_token(key: &TokenKey, token: &str, now: i64) -> Result<TokenClaims, TokenError> {
    let (signed, sig) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
    let payload = signed
        .strip_prefix(TOKEN_PREFIX)
        .ok_or(TokenError::Malformed)?;
    let sig = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|_| TokenError::Malformed)?;
    key.mac(signed.as_bytes())
        .verify_slice(&sig)
        .map_err(|_| TokenError::BadSignature)?;
    let raw = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| TokenError::Malformed)?;
    let claims: TokenClaims = serde_json::from_slice(&raw).map_err(|_| TokenError::Malformed)?;
    if claims.v != 1 {
        return Err(TokenError::Malformed);
    }
    if claims.exp <= now {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pepper() -> Pepper {
        Pepper::new(vec![7u8; 32]).unwrap()
    }

    fn token_key() -> TokenKey {
        TokenKey::new(vec![9u8; 32]).unwrap()
    }

    #[test]
    fn generated_key_parses_and_verifies() {
        let p = pepper();
        let k = generate_key(&p).unwrap();
        assert!(k.full.starts_with("clv_"));
        let parsed = parse_key(&k.full).unwrap();
        assert_eq!(parsed.id, k.id);
        assert!(p.verify(parsed.secret, &k.secret_hmac));
        assert_eq!(k.hint, &k.full[k.full.len() - 4..]);
    }

    #[test]
    fn many_generated_keys_parse() {
        // base64url secrets sometimes contain '_' and '-'.
        let p = pepper();
        for _ in 0..500 {
            let k = generate_key(&p).unwrap();
            assert!(parse_key(&k.full).is_some(), "{}", k.full);
        }
    }

    #[test]
    fn wrong_pepper_does_not_verify() {
        let k = generate_key(&pepper()).unwrap();
        let other = Pepper::new(vec![8u8; 32]).unwrap();
        let parsed = parse_key(&k.full).unwrap();
        assert!(!other.verify(parsed.secret, &k.secret_hmac));
    }

    #[test]
    fn checksum_catches_a_changed_character() {
        let k = generate_key(&pepper()).unwrap();
        let mut b = k.full.into_bytes();
        let i = 20;
        b[i] = if b[i] == b'A' { b'B' } else { b'A' };
        assert!(parse_key(std::str::from_utf8(&b).unwrap()).is_none());
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "clv_",
            "sk-ant-api03-xyz",
            "clv_short_x_00000000",
            "clvt_abc.def",
        ] {
            assert!(parse_key(s).is_none(), "{s}");
        }
    }

    #[test]
    fn short_secrets_are_refused() {
        assert!(Pepper::new(vec![0u8; 31]).is_err());
        assert!(TokenKey::new(vec![0u8; 16]).is_err());
    }

    fn claims(exp: i64) -> TokenClaims {
        TokenClaims {
            v: 1,
            kid: "abcdefghijkl".into(),
            tid: Uuid::now_v7(),
            iat: 100,
            exp,
            jti: Uuid::now_v7(),
            pol: Some(Policy {
                models: Some(vec!["claude-haiku-*".into()]),
                ..Policy::default()
            }),
        }
    }

    #[test]
    fn token_round_trips() {
        let c = claims(1000);
        let t = sign_token(&token_key(), &c);
        assert!(t.starts_with("clvt_"));
        assert_eq!(verify_token(&token_key(), &t, 999).unwrap(), c);
    }

    #[test]
    fn expired_token_is_rejected() {
        let t = sign_token(&token_key(), &claims(1000));
        assert_eq!(
            verify_token(&token_key(), &t, 1000),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let t = sign_token(&token_key(), &claims(1000));
        let (signed, sig) = t.rsplit_once('.').unwrap();
        let other = sign_token(&token_key(), &claims(99999));
        let (other_signed, _) = other.rsplit_once('.').unwrap();
        assert_ne!(signed, other_signed);
        let forged = format!("{other_signed}.{sig}");
        assert_eq!(
            verify_token(&token_key(), &forged, 0),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn token_from_another_key_is_rejected() {
        let t = sign_token(&TokenKey::new(vec![1u8; 32]).unwrap(), &claims(1000));
        assert_eq!(
            verify_token(&token_key(), &t, 0),
            Err(TokenError::BadSignature)
        );
    }
}
