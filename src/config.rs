use std::{env, fmt, num::ParseIntError};

use thiserror::Error;

use crate::clients::domain::ClientRegistrationLimits;

#[path = "config_admin.rs"]
mod config_admin;
#[path = "config_audit.rs"]
mod config_audit;
#[path = "config_limits.rs"]
mod config_limits;
#[path = "config_parsing.rs"]
mod config_parsing;
#[path = "config_proxy.rs"]
mod config_proxy;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
pub use crate::sessions::domain::{
    DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS, DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
};
use config_admin::admin_token_from_env;
use config_audit::audit_retention_from_env;
use config_limits::{
    client_registration_limits_from_env, parse_auth_limiter_failure_policy,
    parse_missing_source_ip_policy, security_limits_from_env,
};
use config_parsing::{
    optional_u64, parse_auth_encryption_key_ring, parse_bool, parse_u16, parse_u64, required_env,
};
use config_proxy::trusted_proxies_from_env;

const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;

pub use config_audit::AuditRetentionConfig;
pub use config_limits::SecurityLimits;
pub use config_parsing::{AuthEncryptionKey, AuthEncryptionKeyRing};
pub use config_proxy::TrustedProxies;

// `config_limits` 的测试通过这个路径复用 key ring 解析器；非测试构建没有其他调用方。
#[cfg(test)]
pub(crate) use config_parsing::parse_auth_encryption_key_ring_value;

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

#[derive(Clone)]
pub struct Config {
    pub host: String,
    pub port: u16,
    /// Maximum time for a matched application route to produce a response.
    pub request_timeout_seconds: u64,
    pub issuer_url: String,
    pub admin_token: String,
    pub key_directory: String,
    pub key_rotation_grace_seconds: u64,
    pub cookie_secure: bool,
    /// Development-only compatibility for the OAuth session header.
    pub oauth_session_header_enabled: bool,
    /// Allows opted-in non-browser clients to receive session token in JSON.
    pub session_token_response_enabled: bool,
    pub database_url: String,
    pub redis_url: String,
    pub session_ttl_seconds: u64,
    /// Successful requests renew idle activity, but never extend `session_ttl_seconds`.
    pub session_idle_timeout_seconds: u64,
    /// Oldest active sessions are revoked when this per-user bound is reached.
    pub session_max_concurrent_sessions: u64,
    /// Access token 有效期（秒）。#112：与浏览器会话 TTL 解耦。默认 3600。
    pub access_token_ttl_seconds: u64,
    /// ID token 有效期（秒）。默认与 access token 一致。
    pub id_token_ttl_seconds: u64,
    pub log_filter: String,
    pub auth_encryption_key: AuthEncryptionKey,
    pub auth_encryption_keys: AuthEncryptionKeyRing,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub auth_limiter_failure_policy: AuthLimiterFailurePolicy,
    pub missing_source_ip_policy: MissingSourceIpPolicy,
    pub client_registration_limits: ClientRegistrationLimits,
    /// 可信代理 IP 列表，用于 X-Forwarded-For 解析（#111）。
    pub trusted_proxies: TrustedProxies,
    /// 可配置安全阈值和 TTL（#121）。
    pub security_limits: SecurityLimits,
    /// 审计热表保留和显式归档维护命令配置（#159）。
    pub audit_retention: AuditRetentionConfig,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
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
            .field(
                "session_token_response_enabled",
                &self.session_token_response_enabled,
            )
            .field("database_url", &self.database_url)
            .field("redis_url", &self.redis_url)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field(
                "session_idle_timeout_seconds",
                &self.session_idle_timeout_seconds,
            )
            .field(
                "session_max_concurrent_sessions",
                &self.session_max_concurrent_sessions,
            )
            .field("access_token_ttl_seconds", &self.access_token_ttl_seconds)
            .field("id_token_ttl_seconds", &self.id_token_ttl_seconds)
            .field("log_filter", &self.log_filter)
            .field("auth_encryption_key", &self.auth_encryption_key)
            .field("auth_encryption_keys", &self.auth_encryption_keys)
            .field(
                "auth_limiter_failure_policy",
                &self.auth_limiter_failure_policy,
            )
            .field("missing_source_ip_policy", &self.missing_source_ip_policy)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("security_limits", &self.security_limits)
            .field("audit_retention", &self.audit_retention)
            .finish()
    }
}

struct ConfigValues {
    host: String,
    port: u16,
    request_timeout_seconds: u64,
    issuer_url: String,
    admin_token: String,
    key_directory: String,
    key_rotation_grace_seconds: u64,
    cookie_secure: bool,
    oauth_session_header_enabled: bool,
    session_token_response_enabled: bool,
    database_url: String,
    redis_url: String,
    session_ttl_seconds: u64,
    session_idle_timeout_seconds: u64,
    session_max_concurrent_sessions: u64,
    access_token_ttl_seconds: u64,
    id_token_ttl_seconds: u64,
    log_filter: String,
    auth_encryption_key: AuthEncryptionKey,
    auth_encryption_keys: AuthEncryptionKeyRing,
    webauthn_rp_id: String,
    webauthn_origin: String,
    auth_limiter_failure_policy: AuthLimiterFailurePolicy,
    missing_source_ip_policy: MissingSourceIpPolicy,
    client_registration_limits: ClientRegistrationLimits,
    trusted_proxies: TrustedProxies,
    security_limits: SecurityLimits,
    audit_retention: AuditRetentionConfig,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv();
        let host = env::var("APP_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
        let port = parse_u16(
            "APP_PORT",
            env::var("APP_PORT").ok().as_deref().unwrap_or("3000"),
        )?;
        let request_timeout_seconds = optional_u64(
            "REQUEST_TIMEOUT_SECONDS",
            DEFAULT_REQUEST_TIMEOUT_SECONDS,
        )?;
        let database_url = required_env("DATABASE_URL")?;
        let redis_url = required_env("REDIS_URL")?;
        let auth_encryption_keys = parse_auth_encryption_key_ring()?;
        let auth_encryption_key = auth_encryption_keys.active_key().clone();
        // APP_ISSUER 写入 JWT iss claim 和 Discovery；缺失时选择启动即失败而不是回退到 host:port。
        let issuer_url = required_env("APP_ISSUER")?;
        let issuer =
            url::Url::parse(&issuer_url).map_err(|_| ConfigError::InvalidValue("APP_ISSUER"))?;
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| issuer.host_str().unwrap_or_default().to_owned());
        let webauthn_origin = env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| issuer_url.clone());
        let client_registration_limits = client_registration_limits_from_env()?;
        let admin_token = admin_token_from_env()?;
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
        let session_token_response_enabled = parse_bool(
            "SESSION_TOKEN_RESPONSE_ENABLED",
            env::var("SESSION_TOKEN_RESPONSE_ENABLED")
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
        let session_idle_timeout_seconds = parse_u64(
            "SESSION_IDLE_TIMEOUT_SECONDS",
            env::var("SESSION_IDLE_TIMEOUT_SECONDS")
                .ok()
                .as_deref()
                .unwrap_or("1800"),
        )?;
        let session_max_concurrent_sessions = parse_u64(
            "SESSION_MAX_CONCURRENT_SESSIONS",
            env::var("SESSION_MAX_CONCURRENT_SESSIONS")
                .ok()
                .as_deref()
                .unwrap_or("5"),
        )?;
        // #112：access/id token TTL 与浏览器会话 TTL 解耦，默认 3600 秒（1 小时）。
        let access_token_ttl_seconds = optional_u64("ACCESS_TOKEN_TTL_SECONDS", 3600)?;
        let id_token_ttl_seconds = optional_u64("ID_TOKEN_TTL_SECONDS", 3600)?;
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
        let trusted_proxies = trusted_proxies_from_env()?;
        let security_limits = security_limits_from_env()?;
        let audit_retention = audit_retention_from_env()?;

        Self::from_values_with_log(ConfigValues {
            host,
            port,
            request_timeout_seconds,
            issuer_url: issuer_url.clone(),
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            session_idle_timeout_seconds,
            session_max_concurrent_sessions,
            access_token_ttl_seconds,
            id_token_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
            client_registration_limits,
            trusted_proxies,
            security_limits,
            audit_retention,
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
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            issuer_url: issuer_url.clone(),
            admin_token: String::new(),
            key_directory: "data/keys".to_owned(),
            key_rotation_grace_seconds: 604_800,
            cookie_secure: true,
            oauth_session_header_enabled: true,
            session_token_response_enabled: false,
            database_url,
            redis_url,
            session_ttl_seconds,
            session_idle_timeout_seconds: DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
            session_max_concurrent_sessions: DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
            access_token_ttl_seconds: 3600,
            id_token_ttl_seconds: 3600,
            log_filter: "chenxing_auth=debug".to_owned(),
            auth_encryption_key: AuthEncryptionKey::new([0_u8; 32]),
            auth_encryption_keys: AuthEncryptionKeyRing::single(AuthEncryptionKey::new([0_u8; 32])),
            webauthn_rp_id: "localhost".to_owned(),
            webauthn_origin: format!("http://localhost:{port}"),
            auth_limiter_failure_policy: AuthLimiterFailurePolicy::FailClosed,
            missing_source_ip_policy: MissingSourceIpPolicy::Skip,
            client_registration_limits: ClientRegistrationLimits::default(),
            trusted_proxies: TrustedProxies::none(),
            security_limits: SecurityLimits::default(),
            audit_retention: AuditRetentionConfig::default(),
        })
    }

    fn from_values_with_log(values: ConfigValues) -> Result<Self, ConfigError> {
        let ConfigValues {
            host,
            port,
            request_timeout_seconds,
            issuer_url,
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            session_idle_timeout_seconds,
            session_max_concurrent_sessions,
            access_token_ttl_seconds,
            id_token_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
            client_registration_limits,
            trusted_proxies,
            security_limits,
            audit_retention,
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
        if request_timeout_seconds == 0 {
            return Err(ConfigError::InvalidValue("REQUEST_TIMEOUT_SECONDS"));
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
        if session_idle_timeout_seconds == 0 {
            return Err(ConfigError::InvalidValue("SESSION_IDLE_TIMEOUT_SECONDS"));
        }
        if session_max_concurrent_sessions == 0 {
            return Err(ConfigError::InvalidValue(
                "SESSION_MAX_CONCURRENT_SESSIONS",
            ));
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
        if admin_token.is_empty() {
            tracing::warn!("ADMIN_TOKEN not set: all admin APIs are disabled until configured");
        }
        // #111：未配置可信代理时告警。生产反向代理部署必须设置 TRUSTED_PROXIES，
        // 否则按源限流退化为代理内网 IP 作 key，全服务共享额度（自我 DoS 风险）。
        if trusted_proxies.is_empty() {
            tracing::warn!(
                "TRUSTED_PROXIES not set: X-Forwarded-For is ignored and all client \
                 IPs resolve to the direct peer. Set TRUSTED_PROXIES if behind a proxy."
            );
        }
        // #112：access token 超过 24 小时告警（无状态 JWT 撤销窗口风险）。
        const DAY: u64 = 86_400;
        if access_token_ttl_seconds > DAY {
            tracing::warn!(
                access_token_ttl_seconds,
                "ACCESS_TOKEN_TTL_SECONDS > 24h: stateless JWT revocation exposure"
            );
        }
        if id_token_ttl_seconds > DAY {
            tracing::warn!(id_token_ttl_seconds, "ID_TOKEN_TTL_SECONDS > 24h");
        }

        Ok(Self {
            host,
            port,
            request_timeout_seconds,
            issuer_url,
            admin_token,
            key_directory,
            key_rotation_grace_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
            session_idle_timeout_seconds,
            session_max_concurrent_sessions,
            access_token_ttl_seconds,
            id_token_ttl_seconds,
            log_filter,
            auth_encryption_key,
            auth_encryption_keys,
            webauthn_rp_id,
            webauthn_origin,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
            client_registration_limits,
            trusted_proxies,
            security_limits,
            audit_retention,
        })
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
