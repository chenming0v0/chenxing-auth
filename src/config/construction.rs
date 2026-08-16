use std::env;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use crate::clients::domain::ClientRegistrationLimits;
use crate::redis_keyspace::RedisKeyspace;
use crate::web_dist::{DEFAULT_WEB_DIST_DIR, WEB_DIST_DIR_ENV};

use super::admin::admin_token_from_env;
use super::audit::{AuditRetentionConfig, audit_retention_from_env};
use super::limits::{
    SecurityLimits, client_registration_limits_from_env, parse_auth_limiter_failure_policy,
    parse_missing_source_ip_policy, security_limits_from_env,
};
use super::parsing::{
    AuthEncryptionKey, AuthEncryptionKeyRing, optional_u64, parse_auth_encryption_key_ring,
    parse_bool, parse_u16, parse_u64, required_env,
};
use super::proxy::{TrustedProxies, trusted_proxies_from_env};
use super::security::{
    DEFAULT_KEY_ACTIVATION_DELAY_SECONDS, DEFAULT_KEY_ROTATION_GRACE_SECONDS,
    DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS, DEFAULT_TOKEN_TTL_SECONDS,
    validate_activation_delay, validate_production_activation_delay, validate_session_lifetimes,
    validate_token_and_key_lifetimes,
};
use super::{
    Config, ConfigError, DEFAULT_HTTP_GRACEFUL_DRAIN_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS,
    normalize_issuer_url,
};

mod test_construction;

struct ConfigValues {
    host: String,
    port: u16,
    request_timeout_seconds: u64,
    http_graceful_drain_seconds: u64,
    issuer_url: Option<String>,
    legacy_issuer_import: Option<String>,
    admin_token: String,
    key_directory: String,
    web_dist_dir: String,
    key_rotation_grace_seconds: u64,
    key_rotation_skew_allowance_seconds: u64,
    key_activation_delay_seconds: u64,
    cookie_secure: bool,
    oauth_session_header_enabled: bool,
    session_token_response_enabled: bool,
    oauth_provider_loopback_enabled: bool,
    database_url: String,
    redis_url: String,
    redis_keyspace: RedisKeyspace,
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
    webauthn_rp_id_explicit: bool,
    webauthn_origin_explicit: bool,
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
        let http_graceful_drain_seconds = optional_u64(
            "HTTP_GRACEFUL_DRAIN_SECONDS",
            DEFAULT_HTTP_GRACEFUL_DRAIN_SECONDS,
        )?;
        let database_url = required_env("DATABASE_URL")?;
        let redis_url = required_env("REDIS_URL")?;
        let redis_keyspace = match env::var(RedisKeyspace::ENV_NAME) {
            Ok(value) => RedisKeyspace::new(&value)
                .map_err(|_| ConfigError::InvalidValue(RedisKeyspace::ENV_NAME))?,
            Err(env::VarError::NotPresent) => RedisKeyspace::default(),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(ConfigError::InvalidValue(RedisKeyspace::ENV_NAME));
            }
        };
        let auth_encryption_keys = parse_auth_encryption_key_ring()?;
        let auth_encryption_key = auth_encryption_keys.active_key().clone();
        // 新部署允许先启动依赖与初始化前端，再把固定 Issuer 写入数据库。旧部署的
        // APP_ISSUER 仍作为一次性导入来源，真正的优先级在 main 启动路径解析。
        let legacy_issuer_import = env::var("APP_ISSUER")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let webauthn_rp_id_override = env::var("WEBAUTHN_RP_ID")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let webauthn_origin_override = env::var("WEBAUTHN_ORIGIN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let webauthn_rp_id_explicit = webauthn_rp_id_override.is_some();
        let webauthn_origin_explicit = webauthn_origin_override.is_some();
        let webauthn_rp_id = webauthn_rp_id_override.unwrap_or_else(|| "localhost".to_owned());
        let webauthn_origin =
            webauthn_origin_override.unwrap_or_else(|| "http://localhost".to_owned());
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
        // Issue #316：跨实例时钟偏差容忍。默认 1 小时，上限校验在
        // `validate_token_and_key_lifetimes`（不允许超过保留窗口本身）。
        let key_rotation_skew_allowance_raw = env::var("KEY_ROTATION_SKEW_ALLOWANCE_SECONDS")
            .unwrap_or_else(|_| DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS.to_string());
        let key_rotation_skew_allowance_seconds = parse_u64(
            "KEY_ROTATION_SKEW_ALLOWANCE_SECONDS",
            &key_rotation_skew_allowance_raw,
        )?;
        // Issue #454：新公钥先进入 JWKS，等缓存与跨实例同步窗口过完再签发。
        let key_activation_delay_raw = env::var("KEY_ACTIVATION_DELAY_SECONDS")
            .unwrap_or_else(|_| DEFAULT_KEY_ACTIVATION_DELAY_SECONDS.to_string());
        let key_activation_delay_seconds =
            parse_u64("KEY_ACTIVATION_DELAY_SECONDS", &key_activation_delay_raw)?;
        validate_production_activation_delay(
            key_activation_delay_seconds,
            key_rotation_grace_seconds,
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
        // Issue #343：回环/明文 http 开发例外默认关闭（生产 fail-closed），
        // 只在本机联调外部 IdP 时显式开启。
        let oauth_provider_loopback_enabled = parse_bool(
            "OAUTH_PROVIDER_LOOPBACK_ENABLED",
            env::var("OAUTH_PROVIDER_LOOPBACK_ENABLED")
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

        Self::from_validated_values(ConfigValues {
            host,
            port,
            request_timeout_seconds,
            http_graceful_drain_seconds,
            issuer_url: None,
            legacy_issuer_import,
            admin_token,
            key_directory,
            web_dist_dir,
            key_rotation_grace_seconds,
            key_rotation_skew_allowance_seconds,
            key_activation_delay_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            oauth_provider_loopback_enabled,
            database_url,
            redis_url,
            redis_keyspace,
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
            webauthn_rp_id_explicit,
            webauthn_origin_explicit,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
            client_registration_limits,
            trusted_proxies,
            security_limits,
            audit_retention,
        })
    }

    fn from_validated_values(values: ConfigValues) -> Result<Self, ConfigError> {
        let ConfigValues {
            host,
            port,
            request_timeout_seconds,
            http_graceful_drain_seconds,
            issuer_url,
            legacy_issuer_import,
            admin_token,
            key_directory,
            web_dist_dir,
            key_rotation_grace_seconds,
            key_rotation_skew_allowance_seconds,
            key_activation_delay_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            oauth_provider_loopback_enabled,
            database_url,
            redis_url,
            redis_keyspace,
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
            webauthn_rp_id_explicit,
            webauthn_origin_explicit,
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
        if http_graceful_drain_seconds == 0 {
            return Err(ConfigError::InvalidValue("HTTP_GRACEFUL_DRAIN_SECONDS"));
        }
        let issuer_url = issuer_url
            .map(|value| normalize_issuer_url(&value))
            .transpose()?;
        let issuer = issuer_url
            .as_deref()
            .map(|value| parse_root_http_url(value, "APP_ISSUER"))
            .transpose()?;
        if let Some(issuer) = issuer.as_ref() {
            validate_cookie_security(issuer, cookie_secure)?;
        }
        // Fail closed on a bad filter before Config exists as a value. The
        // error only names `RUST_LOG`; it never formats tokens, URLs, or keys.
        // Posture warnings stay data until `main` installs a subscriber.
        super::parse_log_filter(&log_filter)?;
        if database_url.trim().is_empty() {
            return Err(ConfigError::MissingValue("DATABASE_URL"));
        }
        if redis_url.trim().is_empty() {
            return Err(ConfigError::MissingValue("REDIS_URL"));
        }
        // #365：三个会话参数不仅有下界（0 表示「会话签发即过期 / 不允许多会话」），
        // 还有上界——`SESSION_TTL_SECONDS` 直接成为 Redis `SET ... EX` 的 TTL，
        // Redis 整数上限是 i64，u64::MAX 秒的配置会让每次会话写入报
        // `ERR invalid expire time`（自伤型 DoS）。越界在这里拒绝，
        // 报错指向配置项而不是 Redis。
        validate_session_lifetimes(
            session_ttl_seconds,
            session_idle_timeout_seconds,
            session_max_concurrent_sessions,
        )?;
        validate_token_and_key_lifetimes(
            key_rotation_grace_seconds,
            key_rotation_skew_allowance_seconds,
            access_token_ttl_seconds,
            id_token_ttl_seconds,
        )?;
        validate_activation_delay(key_activation_delay_seconds, key_rotation_grace_seconds)?;
        if webauthn_rp_id.trim().is_empty() {
            return Err(ConfigError::InvalidValue("WEBAUTHN_RP_ID"));
        }
        parse_root_http_url(&webauthn_origin, "WEBAUTHN_ORIGIN")?;
        Ok(Self {
            host,
            port,
            request_timeout_seconds,
            http_graceful_drain_seconds,
            issuer: issuer_url
                .as_deref()
                .map(super::IssuerUrl::parse)
                .transpose()?,
            legacy_issuer_import,
            admin_token,
            key_directory,
            web_dist_dir,
            key_rotation_grace_seconds,
            key_rotation_skew_allowance_seconds,
            key_activation_delay_seconds,
            cookie_secure,
            oauth_session_header_enabled,
            session_token_response_enabled,
            oauth_provider_loopback_enabled,
            database_url,
            redis_url,
            redis_keyspace,
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
            webauthn_rp_id_explicit,
            webauthn_origin_explicit,
            auth_limiter_failure_policy,
            missing_source_ip_policy,
            client_registration_limits,
            trusted_proxies,
            security_limits,
            audit_retention,
        })
    }

    pub(crate) fn validate_cookie_security(&self) -> Result<(), ConfigError> {
        self.issuer.as_ref().map_or(Ok(()), |issuer| {
            validate_cookie_security(issuer.parsed(), self.cookie_secure)
        })
    }
}

pub(crate) fn parse_root_http_url(
    value: &str,
    name: &'static str,
) -> Result<url::Url, ConfigError> {
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

pub(crate) fn validate_cookie_security(
    issuer: &url::Url,
    cookie_secure: bool,
) -> Result<(), ConfigError> {
    if issuer.scheme() == "http" && !is_loopback_http_issuer(issuer) {
        return Err(ConfigError::InvalidValue("APP_ISSUER"));
    }
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
#[path = "construction_tests.rs"]
mod tests;
