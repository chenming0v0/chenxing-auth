use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use crate::clients::domain::ClientRegistrationLimits;
use crate::redis_keyspace::RedisKeyspace;
use crate::web_dist::DEFAULT_WEB_DIST_DIR;

use super::super::audit::AuditRetentionConfig;
use super::super::parsing::{AuthEncryptionKey, AuthEncryptionKeyRing};
use super::super::proxy::TrustedProxies;
use super::super::security::{
    DEFAULT_KEY_ROTATION_GRACE_SECONDS, DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
    DEFAULT_TOKEN_TTL_SECONDS,
};
use super::super::{
    Config, ConfigError, DEFAULT_HTTP_GRACEFUL_DRAIN_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS, DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
};
use super::ConfigValues;

impl Config {
    pub fn from_values(
        host: String,
        port: u16,
        database_url: String,
        redis_url: String,
        session_ttl_seconds: u64,
    ) -> Result<Self, ConfigError> {
        Self::from_values_with_issuer(
            host.clone(),
            port,
            format!("http://{host}:{port}"),
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
            http_graceful_drain_seconds: DEFAULT_HTTP_GRACEFUL_DRAIN_SECONDS,
            issuer_url: Some(issuer_url),
            legacy_issuer_import: None,
            admin_token: String::new(),
            key_directory: "data/keys".to_owned(),
            web_dist_dir: DEFAULT_WEB_DIST_DIR.to_owned(),
            key_rotation_grace_seconds: DEFAULT_KEY_ROTATION_GRACE_SECONDS,
            key_rotation_skew_allowance_seconds: DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS,
            // 测试套件必须立即激活，否则每个 rotate() 都要等 65 秒。生产 from_env 默认 65。
            key_activation_delay_seconds: 0,
            cookie_secure: true,
            oauth_session_header_enabled: true,
            session_token_response_enabled: false,
            oauth_provider_loopback_enabled: false,
            database_url,
            redis_url,
            redis_keyspace: RedisKeyspace::default(),
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
            webauthn_rp_id_explicit: true,
            webauthn_origin_explicit: true,
            auth_limiter_failure_policy: AuthLimiterFailurePolicy::FailClosed,
            missing_source_ip_policy: MissingSourceIpPolicy::Skip,
            client_registration_limits: ClientRegistrationLimits::default(),
            trusted_proxies: TrustedProxies::none(),
            security_limits: super::super::limits::SecurityLimits::default(),
            audit_retention: AuditRetentionConfig::default(),
        })
    }
}
