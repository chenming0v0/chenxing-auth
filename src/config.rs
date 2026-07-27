use std::{env, num::ParseIntError};

use thiserror::Error;

#[derive(Debug, Clone)]
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
        let issuer_url = env::var("APP_ISSUER").unwrap_or_else(|_| format!("http://{host}:{port}"));
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
            issuer_url,
            admin_token,
            key_directory,
            cookie_secure,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter,
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
            issuer_url,
            admin_token: String::new(),
            key_directory: "data/keys".to_owned(),
            cookie_secure: true,
            database_url,
            redis_url,
            session_ttl_seconds,
            log_filter: "chenxing_auth=debug".to_owned(),
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
        })
    }
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
