use std::env;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use crate::clients::domain::ClientRegistrationLimits;
use crate::web_dist::{DEFAULT_WEB_DIST_DIR, WEB_DIST_DIR_ENV};

use super::config_admin::admin_token_from_env;
use super::config_audit::{AuditRetentionConfig, audit_retention_from_env};
use super::config_limits::{
    SecurityLimits, client_registration_limits_from_env, parse_auth_limiter_failure_policy,
    parse_missing_source_ip_policy, security_limits_from_env,
};
use super::config_parsing::{
    AuthEncryptionKey, AuthEncryptionKeyRing, optional_u64, parse_auth_encryption_key_ring,
    parse_bool, parse_u16, parse_u64, required_env,
};
use super::config_proxy::{TrustedProxies, trusted_proxies_from_env};
use super::config_security::{
    DEFAULT_KEY_ROTATION_GRACE_SECONDS, DEFAULT_TOKEN_TTL_SECONDS, validate_token_and_key_lifetimes,
};
use super::{
    Config, ConfigError, DEFAULT_REQUEST_TIMEOUT_SECONDS, DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
    DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
};

struct ConfigValues {
    host: String,
    port: u16,
    request_timeout_seconds: u64,
    issuer_url: String,
    admin_token: String,
    key_directory: String,
    web_dist_dir: String,
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
        let request_timeout_seconds =
            optional_u64("REQUEST_TIMEOUT_SECONDS", DEFAULT_REQUEST_TIMEOUT_SECONDS)?;
        let database_url = required_env("DATABASE_URL")?;
        let redis_url = required_env("REDIS_URL")?;
        let auth_encryption_keys = parse_auth_encryption_key_ring()?;
        let auth_encryption_key = auth_encryption_keys.active_key().clone();
        // APP_ISSUER 写入 JWT iss claim 和 Discovery；缺失时选择启动即失败而不是回退到 host:port。
        let issuer_url = required_env("APP_ISSUER")?;
        let issuer = parse_root_http_url(&issuer_url, "APP_ISSUER")?;
        let webauthn_rp_id = env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| issuer.host_str().unwrap_or_default().to_owned());
        let webauthn_origin = env::var("WEBAUTHN_ORIGIN").unwrap_or_else(|_| issuer_url.clone());
        let client_registration_limits = client_registration_limits_from_env()?;
        let admin_token = admin_token_from_env()?;
        let key_directory = env::var("KEY_DIRECTORY").unwrap_or_else(|_| "data/keys".to_owned());
        // 未设置时用默认相对路径；设置成空值则保留空值，由启动期解析明确拒绝，
        // 而不是静默回退（回退到工作目录会把 .env 和私钥变成可下载文件，#303）。
        let web_dist_dir =
            env::var(WEB_DIST_DIR_ENV).unwrap_or_else(|_| DEFAULT_WEB_DIST_DIR.to_owned());
        let key_rotation_grace_raw = env::var("KEY_ROTATION_GRACE_SECONDS")
            .unwrap_or_else(|_| DEFAULT_KEY_ROTATION_GRACE_SECONDS.to_string());
        let key_rotation_grace_seconds =
            parse_u64("KEY_ROTATION_GRACE_SECONDS", &key_rotation_grace_raw)?;
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
        let access_token_ttl_seconds =
            optional_u64("ACCESS_TOKEN_TTL_SECONDS", DEFAULT_TOKEN_TTL_SECONDS)?;
        let id_token_ttl_seconds = optional_u64("ID_TOKEN_TTL_SECONDS", DEFAULT_TOKEN_TTL_SECONDS)?;
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
            web_dist_dir,
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
            web_dist_dir: DEFAULT_WEB_DIST_DIR.to_owned(),
            key_rotation_grace_seconds: DEFAULT_KEY_ROTATION_GRACE_SECONDS,
            cookie_secure: true,
            oauth_session_header_enabled: true,
            session_token_response_enabled: false,
            database_url,
            redis_url,
            session_ttl_seconds,
            session_idle_timeout_seconds: DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS,
            session_max_concurrent_sessions: DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
            access_token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            id_token_ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
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
            web_dist_dir,
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
        let issuer = parse_root_http_url(&issuer_url, "APP_ISSUER")?;
        validate_cookie_security(&issuer, cookie_secure)?;
        if cookie_secure && issuer.scheme() == "http" {
            tracing::warn!(
                issuer_scheme = %issuer.scheme(),
                "COOKIE_SECURE=true with an HTTP APP_ISSUER: browsers may reject the Secure cookies"
            );
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
            return Err(ConfigError::InvalidValue("SESSION_MAX_CONCURRENT_SESSIONS"));
        }
        validate_token_and_key_lifetimes(
            key_rotation_grace_seconds,
            access_token_ttl_seconds,
            id_token_ttl_seconds,
        )?;
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        parse_root_http_url(&webauthn_origin, "WEBAUTHN_ORIGIN")?;
        // Issue #305：告警必须如实说明这只关掉一条通道。旧文案声称「all admin APIs
        // are disabled」，但代码里空 Token 只让 `AdminAuthenticator::is_valid` 恒假，
        // 也就是只拒绝 Bearer 系统 Token；浏览器 Session 通道（HttpOnly Session
        // Cookie + CSRF 双 Cookie 绑定 + 角色权限）不受影响，管理面依然可用。
        // 按旧文案理解会得出「不配 Token 就等于关闭管理面」的错误安全结论。
        if admin_token.is_empty() {
            tracing::warn!(
                "ADMIN_TOKEN not set: the system Bearer token channel for admin APIs is \
                 disabled. Authenticated browser sessions with sufficient roles and valid \
                 CSRF binding can still use the admin APIs; the first-owner bootstrap \
                 endpoint stays public while no owner exists."
            );
        }
        // #111：未配置可信代理时告警。生产反向代理部署必须设置 TRUSTED_PROXIES，
        // 否则按源限流退化为代理内网 IP 作 key，全服务共享额度（自我 DoS 风险）。
        if trusted_proxies.is_empty() {
            tracing::warn!(
                "TRUSTED_PROXIES not set: X-Forwarded-For is ignored and all client \
                 IPs resolve to the direct peer. Set TRUSTED_PROXIES if behind a proxy."
            );
        }
        Ok(Self {
            host,
            port,
            request_timeout_seconds,
            issuer_url,
            admin_token,
            key_directory,
            web_dist_dir,
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

    pub(crate) fn validate_cookie_security(&self) -> Result<(), ConfigError> {
        let issuer = parse_root_http_url(&self.issuer_url, "APP_ISSUER")?;
        validate_cookie_security(&issuer, self.cookie_secure)
    }
}

fn parse_root_http_url(value: &str, name: &'static str) -> Result<url::Url, ConfigError> {
    let url = url::Url::parse(value).map_err(|_| ConfigError::InvalidValue(name))?;
    // URL userinfo 是凭据材料；错误只报告配置项名称，绝不携带原始值。
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::InvalidValue(name));
    }
    Ok(url)
}

fn validate_cookie_security(issuer: &url::Url, cookie_secure: bool) -> Result<(), ConfigError> {
    if cookie_secure || is_loopback_http_issuer(issuer) {
        return Ok(());
    }
    Err(ConfigError::InvalidValue("COOKIE_SECURE"))
}

fn is_loopback_http_issuer(issuer: &url::Url) -> bool {
    issuer.scheme() == "http"
        && issuer.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        })
}

#[cfg(test)]
#[path = "config_construction_tests.rs"]
mod tests;
