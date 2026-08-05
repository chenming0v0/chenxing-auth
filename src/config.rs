use std::{env, fmt, num::ParseIntError};

use thiserror::Error;

use crate::clients::domain::ClientRegistrationLimits;

#[path = "config_limits.rs"]
mod config_limits;
#[path = "config_parsing.rs"]
mod config_parsing;
#[path = "config_proxy.rs"]
mod config_proxy;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use config_limits::{
    client_registration_limits_from_env, parse_auth_limiter_failure_policy,
    parse_missing_source_ip_policy, security_limits_from_env,
};
use config_parsing::{
    optional_u64, parse_auth_encryption_key_ring, parse_bool, parse_u16, parse_u64, required_env,
};
use config_proxy::trusted_proxies_from_env;

pub use config_limits::SecurityLimits;
pub use config_parsing::{AuthEncryptionKey, AuthEncryptionKeyRing};
pub use config_proxy::TrustedProxies;

// `config_limits` 的测试通过这个路径复用 key ring 解析器。
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
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("issuer_url", &self.issuer_url)
            .field("admin_token", &"REDACTED")
            .field("key_directory", &self.key_directory)
            .field("key_rotation_grace_seconds", &self.key_rotation_grace_seconds)
            .field("cookie_secure", &self.cookie_secure)
            .field("oauth_session_header_enabled", &self.oauth_session_header_enabled)
            .field("session_token_response_enabled", &self.session_token_response_enabled)
            .field("database_url", &self.database_url)
            .field("redis_url", &self.redis_url)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .field("access_token_ttl_seconds", &self.access_token_ttl_seconds)
            .field("id_token_ttl_seconds", &self.id_token_ttl_seconds)
            .field("log_filter", &self.log_filter)
            .field("auth_encryption_key", &self.auth_encryption_key)
            .field("auth_encryption_keys", &self.auth_encryption_keys)
            .field("auth_limiter_failure_policy", &self.auth_limiter_failure_policy)
            .field("missing_source_ip_policy", &self.missing_source_ip_policy)
            .field("trusted_proxies", &self.trusted_proxies)
            .field("security_limits", &self.security_limits)
            .finish()
    }
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
    session_token_response_enabled: bool,
    database_url: String,
    redis_url: String,
    session_ttl_seconds: u64,
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
        // APP_ISSUER 写入 JWT iss claim 和 Discovery；缺失时选择启动即失败而不是回退到 host:port。
        let issuer_url = required_env("APP_ISSUER")?;
        let issuer =
            url::Url::parse(&issuer_url).map_err(|_| ConfigError::InvalidValue("APP_ISSUER"))?;
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| issuer.host_str().unwrap_or_default().to_owned());
        let webauthn_origin = env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| issuer_url.clone());
        let client_registration_limits = client_registration_limits_from_env()?;
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

        Self::from_values_with_log(ConfigValues {
            host,
            port,
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
        Self::from_values_with_issuer(host, port, issuer_url, database_url, redis_url, session_ttl_seconds)
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
            session_token_response_enabled: false,
            database_url,
            redis_url,
            session_ttl_seconds,
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
            session_token_response_enabled,
            database_url,
            redis_url,
            session_ttl_seconds,
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_session_ttl(session_ttl_seconds: u64) -> Config {
        Config::from_values(
            "127.0.0.1".to_owned(),
            3000,
            "postgres://localhost/chenxing_auth".to_owned(),
            "redis://localhost".to_owned(),
            session_ttl_seconds,
        )
        .expect("valid test configuration")
    }

    /// #112 的核心断言：拉长浏览器会话 TTL 不得同时拉长无状态 access token 的窗口。
    /// 两者的安全权衡完全不同——会话有 HttpOnly、CSRF 绑定且可即时撤销，
    /// access token 是 JWT，撤销只在 userinfo 端点生效。
    #[test]
    fn token_ttls_are_independent_of_the_session_ttl() {
        let week = 604_800;
        let config = config_with_session_ttl(week);

        assert_eq!(config.session_ttl_seconds, week);
        assert_eq!(config.access_token_ttl_seconds, 3600);
        assert_eq!(config.id_token_ttl_seconds, 3600);
        assert_ne!(config.access_token_ttl_seconds, config.session_ttl_seconds);
    }

    /// 会话 TTL 取任何值都不影响令牌 TTL（回归保护：防止再次被同一个字段驱动）。
    #[test]
    fn changing_the_session_ttl_never_moves_the_token_ttls() {
        for session_ttl in [60, 3_600, 86_400, 604_800] {
            let config = config_with_session_ttl(session_ttl);
            assert_eq!(config.session_ttl_seconds, session_ttl);
            assert_eq!(config.access_token_ttl_seconds, 3600);
            assert_eq!(config.id_token_ttl_seconds, 3600);
        }
    }

    /// 测试构造函数不接受新增字段，必须自带安全默认值（`from_values*` 签名保持不变）。
    #[test]
    fn test_constructors_default_to_safe_values() {
        let config = config_with_session_ttl(3600);

        // 未配置可信代理：忽略 XFF，等价于升级前的行为。
        assert!(config.trusted_proxies.is_empty());
        assert_eq!(config.security_limits, SecurityLimits::default());
    }

    #[test]
    fn session_ttl_of_zero_is_still_rejected() {
        let error = Config::from_values(
            "127.0.0.1".to_owned(),
            3000,
            "postgres://localhost/chenxing_auth".to_owned(),
            "redis://localhost".to_owned(),
            0,
        )
        .expect_err("zero session TTL must be rejected");
        assert_eq!(error, ConfigError::InvalidValue("SESSION_TTL_SECONDS"));
    }
}
