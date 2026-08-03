use std::{env, fmt, num::ParseIntError};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use thiserror::Error;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};

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
    cookie_secure: bool,
    database_url: String,
    redis_url: String,
    session_ttl_seconds: u64,
    log_filter: String,
    auth_encryption_key: AuthEncryptionKey,
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
        let auth_encryption_key = parse_auth_encryption_key(&required_env("AUTH_ENCRYPTION_KEY")?)?;
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
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
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
            cookie_secure: true,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter: "chenxing_auth=debug".to_owned(),
            auth_encryption_key: AuthEncryptionKey::new([0_u8; 32]),
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
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
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
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
            auth_encryption_key,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
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
