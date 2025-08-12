use std::collections::HashSet;
use std::env;

use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use base64::Engine;
use dotenvy::dotenv;
use serde::Deserialize;
use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    issuer: String,
    audience: String,
    access_ttl_seconds: i64,
    refresh_ttl_seconds: i64,
    refresh_hash_key_32: [u8; 32],
    jwt_keys: Vec<(String, Vec<u8>)>, // (kid, secret)
    access_cookie_name: String,
    refresh_cookie_name: String,
    active_kid: String,
}

impl Config {
    pub fn jwt_issuer(&self) -> &str {
        &self.issuer
    }
    pub fn jwt_audience(&self) -> &str {
        &self.audience
    }
    pub fn token_ttl_seconds(&self) -> i64 {
        self.access_ttl_seconds
    }
    pub fn refresh_token_ttl_seconds(&self) -> i64 {
        self.refresh_ttl_seconds
    }
    pub fn refresh_hash_key(&self) -> &[u8; 32] {
        &self.refresh_hash_key_32
    }
    pub fn access_cookie_name(&self) -> &str {
        &self.access_cookie_name
    }
    pub fn refresh_cookie_name(&self) -> &str {
        &self.refresh_cookie_name
    }
    pub fn jwt_active_kid(&self) -> &str {
        &self.active_kid
    }
    pub fn jwt_keys(&self) -> &[(String, Vec<u8>)] {
        &self.jwt_keys
    }

    pub fn default() -> Result<Self, ConfigError> {
        // Load .env in dev; no-op in prod if not present.
        let _ = dotenv();

        let issuer = req_var("JWT_ISSUER")?;
        let audience = req_var("JWT_AUDIENCE")?;

        let access_ttl_seconds = parse_i64("ACCESS_TTL_SECONDS")?;
        let refresh_ttl_seconds = parse_i64("REFRESH_TTL_SECONDS")?;

        let refresh_hash_key_b64 = req_var("REFRESH_HASH_KEY_B64")?;
        let refresh_hash_key_vec = decode_b64_any(&refresh_hash_key_b64)
            .map_err(|_| ConfigError::Decode("REFRESH_HASH_KEY_B64"))?;
        if refresh_hash_key_vec.len() != 32 {
            return Err(ConfigError::WrongLen(
                "REFRESH_HASH_KEY_B64 must decode to 32 bytes",
            ));
        }
        let mut refresh_hash_key_32 = [0u8; 32];
        refresh_hash_key_32.copy_from_slice(&refresh_hash_key_vec);

        let active_kid = req_var("JWT_ACTIVE_KID")?;
        let jwt_keys = parse_hs256_keys_json("JWT_HS256_KEYS_JSON")?;

        // Validate keys
        if jwt_keys.is_empty() {
            return Err(ConfigError::Invalid("empty JWT keys"));
        }
        let kids: HashSet<_> = jwt_keys.iter().map(|(k, _)| k).collect();
        if !kids.contains(&active_kid) {
            return Err(ConfigError::Invalid(
                "JWT_ACTIVE_KID not found in JWT_HS256_KEYS_JSON",
            ));
        }

        let access_cookie_name = opt_var("ACCESS_COOKIE_NAME").unwrap_or_else(|| "access".into());
        let refresh_cookie_name =
            opt_var("REFRESH_COOKIE_NAME").unwrap_or_else(|| "refresh".into());

        Ok(Self {
            issuer,
            audience,
            access_ttl_seconds,
            refresh_ttl_seconds,
            refresh_hash_key_32,
            jwt_keys,
            access_cookie_name,
            refresh_cookie_name,
            active_kid,
        })
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("missing env var {0}")]
    Missing(&'static str),
    #[error("invalid env var {0}")]
    Invalid(&'static str),
    #[error("decode error in {0}")]
    Decode(&'static str),
    #[error("{0}")]
    WrongLen(&'static str),
}

fn req_var(key: &'static str) -> Result<String, ConfigError> {
    env::var(key).map_err(|_| ConfigError::Missing(key))
}

fn opt_var(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn parse_i64(key: &'static str) -> Result<i64, ConfigError> {
    let v = req_var(key)?;
    v.parse::<i64>().map_err(|_| ConfigError::Invalid(key))
}

fn decode_b64_any(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    // Try URL-safe (no padding) first, then standard.
    B64_URL.decode(s).or_else(|_| B64_STD.decode(s))
}

#[derive(Deserialize)]
struct HsKey {
    kid: String,
    secret_b64: String,
}

fn parse_hs256_keys_json(key_name: &'static str) -> Result<Vec<(String, Vec<u8>)>, ConfigError> {
    let raw = req_var(key_name)?;
    let parsed: Vec<HsKey> =
        serde_json::from_str(&raw).map_err(|_| ConfigError::Invalid(key_name))?;

    // Deduplicate and decode
    let mut out = Vec::with_capacity(parsed.len());
    let mut seen = std::collections::HashSet::new();
    for k in parsed {
        if !seen.insert(k.kid.clone()) {
            return Err(ConfigError::Invalid("duplicate kid in keys JSON"));
        }
        let secret = decode_b64_any(&k.secret_b64).map_err(|_| ConfigError::Decode(key_name))?;

        // Strongly recommend >= 32 bytes for HS256
        if secret.len() < 32 {
            return Err(ConfigError::WrongLen(
                "HS256 secret must be at least 32 bytes",
            ));
        }
        out.push((k.kid, secret));
    }
    Ok(out)
}
