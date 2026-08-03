use std::{env, fmt, num::ParseIntError};

use thiserror::Error;

#[path = "config_parsing.rs"]
mod config_parsing;
use config_parsing::{parse_auth_encryption_key, parse_bool, parse_u16, parse_u64, required_env};
use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub issuer_url: String,
    pub admin_token: String,
    pub key_directory: String,
    pub key_rotation_grace_seconds: u64,
    pub cookie_secure: bool,
    /// Development-only compatibility for the OAuth session header.
    /// Production configuration keeps this disabled unless explicitly enabled.
    pub oauth_session_header_enabled: bool,
    pub database_url: String,
    pub redis_url: String,
    pub session_ttl_seconds: u64,
    pub log_filter: String,
    pub auth_encryption_key: AuthEncryptionKey,
    pub auth_encryption_keys: AuthEncryptionKeyRing,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub auth_limiter_failure_policy: AuthLimiterFailurePolicy,
    pub missing_source_ip_policy: MissingSourceIpPolicy,
}

#[derive(Clone)]
pub struct AuthEncryptionKey([u8; 32]);

impl AuthEncryptionKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthEncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthEncryptionKey(REDACTED)")
    }
}

#[derive(Clone)]
pub struct AuthEncryptionKeyRing {
    active_kid: String,
    keys: Vec<(String, AuthEncryptionKey)>,
}

impl AuthEncryptionKeyRing {
    pub fn single(key: AuthEncryptionKey) -> Self {
        Self {
            active_kid: "legacy".to_owned(),
            keys: vec![("legacy".to_owned(), key)],
        }
    }

    pub fn from_entries(
        active_kid: String,
        keys: Vec<(String, AuthEncryptionKey)>,
    ) -> Result<Self, ConfigError> {
        if keys.is_empty()
            || active_kid.trim().is_empty()
            || active_kid.len() > 64
            || keys.iter().any(|(kid, _)| kid.is_empty() || kid.len() > 64)
            || keys
                .iter()
                .enumerate()
                .any(|(index, (kid, _))| keys[..index].iter().any(|(known, _)| known == kid))
            || !keys.iter().any(|(kid, _)| kid == &active_kid)
        {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        }
        Ok(Self::new(active_kid, keys))
    }

    pub fn active_kid(&self) -> &str {
        &self.active_kid
    }

    pub fn active_key(&self) -> &AuthEncryptionKey {
        self.key(&self.active_kid)
            .expect("active key must exist in a validated key ring")
    }

    pub fn key(&self, kid: &str) -> Option<&AuthEncryptionKey> {
        self.keys
            .iter()
            .find_map(|(stored_kid, key)| (stored_kid == kid).then_some(key))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &AuthEncryptionKey)> {
        self.keys.iter().map(|(kid, key)| (kid.as_str(), key))
    }

    fn new(active_kid: String, keys: Vec<(String, AuthEncryptionKey)>) -> Self {
        Self { active_kid, keys }
    }
}

impl fmt::Debug for AuthEncryptionKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthEncryptionKeyRing")
            .field("active_kid", &self.active_kid)
            .field(
                "kids",
                &self.keys.iter().map(|(kid, _)| kid).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("issuer_url", &self.issuer_url)
            .field("admin_token", &"REDACTED")
            .field("key_directory", &self.key_directory)
            .field(
                "key_rotation_grace_seconds",
                &self.key_rotation_grace_seconds,
            )
            .field("cookie_secure", &self.cookie_secure)
            .field(
                "oauth_session_header_enabled",
                &self.oauth_session_header_enabled,
            )
            .field("database_url", &self.database_url)
            .field("redis_url", &self.redis_url)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("log_filter", &self.log_filter)
            .field("auth_encryption_key", &self.auth_encryption_key)
            .field("auth_encryption_keys", &self.auth_encryption_keys)
            .field(
                "auth_limiter_failure_policy",
                &self.auth_limiter_failure_policy,
            )
            .field("missing_source_ip_policy", &self.missing_source_ip_policy)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("missing required configuration value: {0}")]
    MissingValue(&'static str),
    #[error("invalid configuration value: {0}")]
    InvalidValue(&'static str),
    #[error("invalid integer configuration value for {name}: {source}")]
    InvalidInteger {
        name: &'static str,
        #[source]
        source: ParseIntError,
    },
}

struct ConfigValues {
    host: String,
    port: u16,
    issuer_url: String,
    admin_token: String,
    key_directory: String,
    key_rotation_grace_seconds: u64,
    cookie_secure: bool,
    oauth_session_header_enabled: bool,
    database_url: String,
    redis_url: String,
    session_ttl_seconds: u64,
    log_filter: String,
    auth_encryption_key: AuthEncryptionKey,
    auth_encryption_keys: AuthEncryptionKeyRing,
    webauthn_rp_id: String,
    webauthn_origin: String,
    auth_limiter_failure_policy: AuthLimiterFailurePolicy,
    missing_source_ip_policy: MissingSourceIpPolicy,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv();
        let host = env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let port = parse_u16(
            "APP_PORT",
            env::var("APP_PORT").ok().as_deref().unwrap_or("3000"),
        )?;
        let database_url = required_env("DATABASE_URL")?;
        let redis_url = required_env("REDIS_URL")?;
        let auth_encryption_keys = parse_auth_encryption_key_ring()?;
        let auth_encryption_key = auth_encryption_keys.active_key().clone();
        let issuer_url = env::var("APP_ISSUER").unwrap_or_else(|_| format!("http://{host}:{port}"));
        let issuer =
            url::Url::parse(&issuer_url).map_err(|_| ConfigError::InvalidValue("APP_ISSUER"))?;
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| issuer.host_str().unwrap_or_default().to_owned());
        let webauthn_origin = env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| issuer_url.clone());
        let admin_token = env::var("ADMIN_TOKEN").unwrap_or_default();
        let key_directory = env::var("KEY_DIRECTORY").unwrap_or_else(|_| "data/keys".to_owned());
        let key_rotation_grace_seconds = parse_u64(
            "KEY_ROTATION_GRACE_SECONDS",
            env::var("KEY_ROTATION_GRACE_SECONDS")
                .ok()
                .as_deref()
                .unwrap_or("604800"),
        )?;
        let cookie_secure = parse_bool(
            "COOKIE_SECURE",
            env::var("COOKIE_SECURE").ok().as_deref().unwrap_or("true"),
        )?;
        let oauth_session_header_enabled = parse_bool(
            "OAUTH_SESSION_HEADER_ENABLED",
            env::var("OAUTH_SESSION_HEADER_ENABLED")
                .ok()
                .as_deref()
                .unwrap_or("false"),
        )?;
        let session_ttl_seconds = parse_u64(
            "SESSION_TTL_SECONDS",
            env::var("SESSION_TTL_SECONDS")
                .ok()
                .as_deref()
                .unwrap_or("604800"),
        )?;
        let log_filter = env::var("RUST_LOG")
            .unwrap_or_else(|_| "chenxing_auth=debug,tower_http=debug".to_owned());
        let auth_limiter_failure_policy = parse_auth_limiter_failure_policy(
            "AUTH_LIMITER_FAILURE_POLICY",
            env::var("AUTH_LIMITER_FAILURE_POLICY")
                .ok()
                .as_deref()
                .unwrap_or("fail-closed"),
        )?;
        let missing_source_ip_policy = parse_missing_source_ip_policy(
            "AUTH_LIMITER_MISSING_SOURCE_IP",
            env::var("AUTH_LIMITER_MISSING_SOURCE_IP")
                .ok()
                .as_deref()
                .unwrap_or("reject"),
        )?;

        Self::from_values_with_log(ConfigValues {
            host,
            port,
            issuer_url: issuer_url.clone(),
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
        })
    }

    pub fn from_values(
        host: String,
        port: u16,
        database_url: String,
        redis_url: String,
        session_ttl_seconds: u64,
    ) -> Result<Self, ConfigError> {
        let issuer_url = format!("http://{host}:{port}");
        Self::from_values_with_issuer(
            host,
            port,
            issuer_url,
            database_url,
            redis_url,
            session_ttl_seconds,
        )
    }

    pub fn from_values_with_issuer(
        host: String,
        port: u16,
        issuer_url: String,
        database_url: String,
        redis_url: String,
        session_ttl_seconds: u64,
    ) -> Result<Self, ConfigError> {
        Self::from_values_with_log(ConfigValues {
            host,
            port,
            issuer_url: issuer_url.clone(),
            admin_token: String::new(),
            key_directory: "data/keys".to_owned(),
            key_rotation_grace_seconds: 604_800,
            cookie_secure: true,
            oauth_session_header_enabled: true,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter: "chenxing_auth=debug".to_owned(),
            auth_encryption_key: AuthEncryptionKey::new([0_u8; 32]),
            auth_encryption_keys: AuthEncryptionKeyRing::single(AuthEncryptionKey::new([0_u8; 32])),
            webauthn_rp_id: "localhost".to_owned(),
            webauthn_origin: format!("http://localhost:{port}"),
            auth_limiter_failure_policy: AuthLimiterFailurePolicy::FailClosed,
            missing_source_ip_policy: MissingSourceIpPolicy::Skip,
        })
    }

    fn from_values_with_log(values: ConfigValues) -> Result<Self, ConfigError> {
        let ConfigValues {
            host,
            port,
            issuer_url,
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
        } = values;
        if host.trim().is_empty() {
            return Err(ConfigError::InvalidValue("APP_HOST"));
        }
        if key_directory.trim().is_empty() {
            return Err(ConfigError::InvalidValue("KEY_DIRECTORY"));
        }
        if port == 0 {
            return Err(ConfigError::InvalidValue("APP_PORT"));
        }
        let issuer =
            url::Url::parse(&issuer_url).map_err(|_| ConfigError::InvalidValue("APP_ISSUER"))?;
        if !matches!(issuer.scheme(), "http" | "https")
            || issuer.host_str().is_none()
            || issuer.path() != "/"
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err(ConfigError::InvalidValue("APP_ISSUER"));
        }
        if database_url.trim().is_empty() {
            return Err(ConfigError::MissingValue("DATABASE_URL"));
        }
        if redis_url.trim().is_empty() {
            return Err(ConfigError::MissingValue("REDIS_URL"));
        }
        if session_ttl_seconds == 0 {
            return Err(ConfigError::InvalidValue("SESSION_TTL_SECONDS"));
        }
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        let origin = url::Url::parse(&webauthn_origin)
            .map_err(|_| ConfigError::InvalidValue("WEBAUTHN_ORIGIN"))?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(ConfigError::InvalidValue("WEBAUTHN_ORIGIN"));
        }

        Ok(Self {
            host,
            port,
            issuer_url,
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
        })
    }
}
fn parse_auth_encryption_key_ring() -> Result<AuthEncryptionKeyRing, ConfigError> {
    let Ok(value) = env::var("AUTH_ENCRYPTION_KEYS") else {
        return Ok(AuthEncryptionKeyRing::single(parse_auth_encryption_key(
            &required_env("AUTH_ENCRYPTION_KEY")?,
        )?));
    };
    let active_kid = env::var("AUTH_ENCRYPTION_ACTIVE_KID")
        .ok()
        .filter(|kid| !kid.trim().is_empty())
        .map(|kid| kid.trim().to_owned());
    parse_auth_encryption_key_ring_value(&value, active_kid.as_deref())
}

fn parse_auth_encryption_key_ring_value(
    value: &str,
    active_kid: Option<&str>,
) -> Result<AuthEncryptionKeyRing, ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
    }

    let mut keys = Vec::new();
    for item in value.split(',') {
        let item = item.trim();
        let Some(entry) = item.strip_prefix("kid=") else {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        };
        let Some((kid, encoded)) = entry.split_once(':') else {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        };
        let kid = kid.trim();
        if kid.is_empty()
            || kid.len() > 64
            || keys.iter().any(|(known, _)| known == kid)
            || encoded.trim().is_empty()
        {
            return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
        }
        let key = parse_auth_encryption_key(encoded)
            .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"))?;
        keys.push((kid.to_owned(), key));
    }
    let active_kid = active_kid
        .filter(|kid| !kid.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| keys[0].0.clone());
    if !keys.iter().any(|(kid, _)| kid == &active_kid) {
        return Err(ConfigError::InvalidValue("AUTH_ENCRYPTION_ACTIVE_KID"));
    }
    AuthEncryptionKeyRing::from_entries(active_kid, keys)
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    #[test]
    fn key_ring_parser_preserves_standard_base64_padding_for_multiple_keys() {
        let current = STANDARD.encode([1_u8; 32]);
        let previous = STANDARD.encode([2_u8; 32]);
        let ring = parse_auth_encryption_key_ring_value(
            &format!("kid=current:{current},kid=previous:{previous}"),
            Some("current"),
        )
        .expect("valid key ring");

        assert_eq!(ring.active_kid(), "current");
        assert_eq!(ring.active_key().as_bytes(), &[1_u8; 32]);
        assert_eq!(
            ring.key("previous").expect("previous key").as_bytes(),
            &[2_u8; 32]
        );
    }

    #[test]
    fn key_ring_parser_rejects_malformed_entries_without_exposing_key_material() {
        for value in [
            "current=not-a-key",
            "kid=current=not-a-key",
            "kid=current:not-a-key",
            "kid=current:",
            "kid=current:not-a-key,kid=",
        ] {
            let error = parse_auth_encryption_key_ring_value(value, None)
                .expect_err("malformed key ring must be rejected");
            assert_eq!(error, ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
            assert!(!error.to_string().contains("not-a-key"));
        }
    }
}

fn parse_auth_limiter_failure_policy(
    name: &'static str,
    value: &str,
) -> Result<AuthLimiterFailurePolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fail-open" | "open" => Ok(AuthLimiterFailurePolicy::FailOpen),
        "fail-closed" | "closed" => Ok(AuthLimiterFailurePolicy::FailClosed),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

fn parse_missing_source_ip_policy(
    name: &'static str,
    value: &str,
) -> Result<MissingSourceIpPolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "skip" => Ok(MissingSourceIpPolicy::Skip),
        "reject" | "fail-closed" => Ok(MissingSourceIpPolicy::Reject),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}
