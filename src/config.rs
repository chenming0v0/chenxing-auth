use std::{fmt, num::ParseIntError};

use thiserror::Error;

use crate::clients::domain::ClientRegistrationLimits;

#[path = "config_admin.rs"]
mod config_admin;
#[path = "config_audit.rs"]
mod config_audit;
#[path = "config_construction.rs"]
mod config_construction;
#[path = "config_limit_bounds.rs"]
mod config_limit_bounds;
#[path = "config_limits.rs"]
mod config_limits;
#[path = "config_parsing.rs"]
mod config_parsing;
#[path = "config_proxy.rs"]
mod config_proxy;
#[path = "config_security.rs"]
mod config_security;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
pub use crate::sessions::domain::{
    DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS, DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
};

const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;

pub use config_audit::AuditRetentionConfig;
// 上界常量必须公开可达 `crate::config::MAX_*`：`for_each_security_limit!` 用绝对路径
// 引用它们，才能在 config 之外（settings）的调用点正确解析。
pub(crate) use config_limit_bounds::for_each_security_limit;
pub use config_limit_bounds::{
    MAX_ACCOUNT_FAILURE_LIMIT, MAX_AUTH_FAILURE_WINDOW_SECONDS, MAX_AUTHORIZATION_CODE_TTL_SECONDS,
    MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING, MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT,
    MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS, MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS,
    MAX_IP_FAILURE_LIMIT, MAX_PENDING_REQUEST_TTL_SECONDS, MAX_PENDING_REQUESTS_GLOBAL,
    MAX_PENDING_REQUESTS_PER_CLIENT, MAX_TOTP_TICKET_FAILURE_LIMIT, MAX_UNAUTHENTICATED_SOURCE_QPS,
};
pub use config_limits::SecurityLimits;
pub use config_parsing::{AuthEncryptionKey, AuthEncryptionKeyRing};
pub use config_proxy::TrustedProxies;
pub use config_security::{DEFAULT_KEY_ROTATION_GRACE_SECONDS, DEFAULT_TOKEN_TTL_SECONDS};

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
            .field("issuer_url", &debug_safe_url(&self.issuer_url))
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
            .field("database_url", &"<redacted>")
            .field("redis_url", &"<redacted>")
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

fn debug_safe_url(value: &str) -> String {
    match url::Url::parse(value) {
        Ok(url) if url.username().is_empty() && url.password().is_none() => value.to_owned(),
        _ => "<redacted>".to_owned(),
    }
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
