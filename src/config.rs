use std::{env, fmt, num::ParseIntError};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use thiserror::Error;

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    pub issuer_url: String,
    pub admin_token: String,
    pub key_directory: String,
    pub cookie_secure: bool,
    pub database_url: String,
    pub redis_url: String,
    pub session_ttl_seconds: u64,
    pub log_filter: String,
    pub auth_encryption_key: AuthEncryptionKey,
    pub auth_encryption_keys: AuthEncryptionKeyRing,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
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
            .field("cookie_secure", &self.cookie_secure)
            .field("database_url", &self.database_url)
            .field("redis_url", &self.redis_url)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("log_filter", &self.log_filter)
            .field("auth_encryption_key", &self.auth_encryption_key)
            .field("auth_encryption_keys", &self.auth_encryption_keys)
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
    cookie_secure: bool,
    database_url: String,
    redis_url: String,
    session_ttl_seconds: u64,
    log_filter: String,
    auth_encryption_key: AuthEncryptionKey,
    auth_encryption_keys: AuthEncryptionKeyRing,
    webauthn_rp_id: String,
    webauthn_origin: String,
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
        let cookie_secure = parse_bool(
            "COOKIE_SECURE",
            env::var("COOKIE_SECURE").ok().as_deref().unwrap_or("true"),
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

        Self::from_values_with_log(ConfigValues {
            host,
            port,
            issuer_url: issuer_url.clone(),
            admin_token,
            key_directory,
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
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
            cookie_secure: true,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter: "chenxing_auth=debug".to_owned(),
            auth_encryption_key: AuthEncryptionKey::new([0_u8; 32]),
            auth_encryption_keys: AuthEncryptionKeyRing::single(AuthEncryptionKey::new([0_u8; 32])),
            webauthn_rp_id: "localhost".to_owned(),
            webauthn_origin: format!("http://localhost:{port}"),
        })
    }

    fn from_values_with_log(values: ConfigValues) -> Result<Self, ConfigError> {
        let ConfigValues {
            host,
            port,
            issuer_url,
            admin_token,
            key_directory,
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
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
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
        })
    }
}

fn parse_auth_encryption_key(value: &str) -> Result<AuthEncryptionKey, ConfigError> {
    let decoded = BASE64
        .decode(value.trim())
        .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEY"))?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| ConfigError::InvalidValue("AUTH_ENCRYPTION_KEY"))?;
    Ok(AuthEncryptionKey::new(bytes))
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

fn required_env(name: &'static str) -> Result<String, ConfigError> {
    let value = env::var(name).map_err(|_| ConfigError::MissingValue(name))?;
    if value.trim().is_empty() {
        return Err(ConfigError::MissingValue(name));
    }
    Ok(value)
}

fn parse_u16(name: &'static str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::InvalidInteger { name, source })
}

fn parse_u64(name: &'static str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::InvalidInteger { name, source })
}

fn parse_bool(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => Err(ConfigError::InvalidValue(name)),
    }
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
