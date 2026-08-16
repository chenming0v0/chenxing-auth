use std::{fmt, num::ParseIntError};

use thiserror::Error;

use crate::clients::domain::ClientRegistrationLimits;
use crate::redis_keyspace::RedisKeyspace;

mod admin;
mod audit;
mod construction;
mod issuer;
mod limit_bounds;
mod limits;
mod parsing;
mod proxy;
mod security;

pub(crate) use construction::{parse_root_http_url, validate_cookie_security};

pub use issuer::{IssuerUrl, normalize_issuer_url};

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
// 会话配置上界常量 `MAX_SESSION_*` 统一来自 security（#365 政策封顶），
// 领域层另有 `crate::sessions::domain::MAX_SESSION_TTL_SECONDS`（#363 运行期 fail-closed
// 边界，表示 OffsetDateTime 可表示范围），二者不在此处重复导出。
pub use crate::sessions::domain::{
    DEFAULT_SESSION_IDLE_TIMEOUT_SECONDS, DEFAULT_SESSION_MAX_CONCURRENT_SESSIONS,
};

const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;
const DEFAULT_HTTP_GRACEFUL_DRAIN_SECONDS: u64 = 15;

pub use audit::AuditRetentionConfig;
// 上界常量必须公开可达 `crate::config::MAX_*`：`for_each_security_limit!` 用绝对路径
// 引用它们，才能在 config 之外（settings）的调用点正确解析。
pub(crate) use limit_bounds::for_each_security_limit;
pub use limit_bounds::{
    MAX_ACCOUNT_FAILURE_LIMIT, MAX_AUTH_FAILURE_WINDOW_SECONDS, MAX_AUTHORIZATION_CODE_TTL_SECONDS,
    MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING, MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT,
    MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS, MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS,
    MAX_IP_FAILURE_LIMIT, MAX_PENDING_REQUEST_TTL_SECONDS, MAX_PENDING_REQUESTS_GLOBAL,
    MAX_PENDING_REQUESTS_PER_CLIENT, MAX_TOTP_TICKET_FAILURE_LIMIT, MAX_UNAUTHENTICATED_SOURCE_QPS,
};
pub use limits::SecurityLimits;
pub use parsing::{AuthEncryptionKey, AuthEncryptionKeyRing};
pub use proxy::TrustedProxies;
pub use security::{
    DEFAULT_KEY_ACTIVATION_DELAY_SECONDS, DEFAULT_KEY_ROTATION_GRACE_SECONDS,
    DEFAULT_KEY_ROTATION_SKEW_ALLOWANCE_SECONDS, DEFAULT_TOKEN_TTL_SECONDS,
    MAX_SESSION_IDLE_TIMEOUT_SECONDS, MAX_SESSION_MAX_CONCURRENT_SESSIONS, MAX_SESSION_TTL_SECONDS,
};

// `limits` 的测试通过这个路径复用 key ring 解析器；非测试构建没有其他调用方。
#[cfg(test)]
pub(crate) use parsing::parse_auth_encryption_key_ring_value;

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
    /// Total time to finish in-flight HTTP connections after a process shutdown
    /// signal. Static SPA/asset responses are not wrapped by
    /// [`Self::request_timeout_seconds`], so a client that stops reading the
    /// body can otherwise keep the Serve future alive indefinitely.
    pub http_graceful_drain_seconds: u64,
    /// 启动时解析出的 Issuer 候选。进入 [`crate::state::AppState`] 后，运行期唯一
    /// 权威是共享的 Issuer runtime；handler 不再读取这份静态配置。
    pub issuer: Option<IssuerUrl>,
    /// 旧部署的 APP_ISSUER 一次性导入候选。
    ///
    /// 该值不参与普通配置校验；只有数据库尚未保存 Issuer 时才会解析并写入。
    pub(crate) legacy_issuer_import: Option<String>,
    pub admin_token: String,
    pub key_directory: String,
    /// 前端构建产物根（`WEB_DIST_DIR`）的原始配置值。
    ///
    /// 这里只保存字符串：真正的解析、canonicalize 和「是可信产物根」的校验发生在
    /// 启动构建 `AppState` 时（见 `crate::web_dist`）。分开的原因是 `migrate` 与
    /// `audit-archive` 子命令同样要加载配置，但它们不托管任何静态资源，不该因为
    /// 主机上没有前端产物而无法执行。
    pub web_dist_dir: String,
    pub key_rotation_grace_seconds: u64,
    /// 跨实例时钟偏差容忍（秒），Issue #316。
    ///
    /// `retired_at` 由退役实例的时钟写入，保留窗口判断却在当前加载实例的时钟上
    /// 进行。该值把窗口关闭边界推到 `retired_at + grace + allowance`，保证时钟偏快
    /// 的实例不会在真实窗口结束前删除共享密钥文件。默认 3600（1 小时），上限是
    /// `KEY_ROTATION_GRACE_SECONDS`；单实例部署可设为 0。
    pub key_rotation_skew_allowance_seconds: u64,
    /// 新公钥进入 JWKS 之后、接管签发之前的等待秒数（Issue #454）。
    ///
    /// 生产环境至少覆盖 JWKS `max-age=60` 与一次 5 秒跨实例同步；测试构造器
    /// 可以使用 0 立即激活。已落盘的 `activate_at` 优先于这个值。
    pub key_activation_delay_seconds: u64,
    pub cookie_secure: bool,
    /// Development-only compatibility for the OAuth session header.
    pub oauth_session_header_enabled: bool,
    /// Allows opted-in non-browser clients to receive session token in JSON.
    pub session_token_response_enabled: bool,
    /// 是否允许外部 IdP 端点使用回环主机与明文 http（Issue #343）。
    ///
    /// 默认关闭（生产 fail-closed）：未开启时回环端点一律拒绝，开启只用于本机
    /// 联调外部 IdP。开启后本服务会把解密后的 client secret 和用户 access token
    /// 发送到这些端点，绝不能在生产开启。
    pub oauth_provider_loopback_enabled: bool,
    pub database_url: String,
    pub redis_url: String,
    pub redis_keyspace: RedisKeyspace,
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
    /// 是否由 WEBAUTHN_* 环境变量显式固定。未固定时，运行期默认值随 Issuer
    /// generation 一起原子更新；显式覆盖永远优先。
    pub webauthn_rp_id_explicit: bool,
    pub webauthn_origin_explicit: bool,
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
        let issuer_url = self
            .issuer
            .as_ref()
            .map(|issuer| debug_safe_url(issuer.as_str()))
            .unwrap_or_else(|| "<unconfigured>".to_owned());
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
            .field(
                "http_graceful_drain_seconds",
                &self.http_graceful_drain_seconds,
            )
            .field("issuer", &issuer_url)
            .field("admin_token", &"REDACTED")
            .field("key_directory", &self.key_directory)
            .field("web_dist_dir", &self.web_dist_dir)
            .field(
                "key_rotation_grace_seconds",
                &self.key_rotation_grace_seconds,
            )
            .field(
                "key_rotation_skew_allowance_seconds",
                &self.key_rotation_skew_allowance_seconds,
            )
            .field(
                "key_activation_delay_seconds",
                &self.key_activation_delay_seconds,
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
            .field(
                "oauth_provider_loopback_enabled",
                &self.oauth_provider_loopback_enabled,
            )
            .field("database_url", &"<redacted>")
            .field("redis_url", &"<redacted>")
            .field("redis_namespace", &self.redis_keyspace)
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
mod tests;
