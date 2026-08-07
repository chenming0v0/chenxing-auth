use std::env;

use crate::auth_limiter::{AuthLimiterFailurePolicy, MissingSourceIpPolicy};
use crate::clients::domain::{
    ClientRegistrationLimits, DEFAULT_ALLOWED_SCOPES, DEFAULT_MAX_REDIRECT_URI_LENGTH,
    DEFAULT_MAX_REDIRECT_URIS, DEFAULT_MAX_SCOPE_LENGTH, DEFAULT_MAX_SCOPES,
};

use super::ConfigError;
use super::config_parsing::{optional_i64, optional_u32, optional_u64};

pub const MAX_UNAUTHENTICATED_SOURCE_QPS: u32 = 1_000;

pub(super) fn parse_auth_limiter_failure_policy(
    name: &'static str,
    value: &str,
) -> Result<AuthLimiterFailurePolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "fail-open" | "open" => Ok(AuthLimiterFailurePolicy::FailOpen),
        "fail-closed" | "closed" => Ok(AuthLimiterFailurePolicy::FailClosed),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

pub(super) fn parse_missing_source_ip_policy(
    name: &'static str,
    value: &str,
) -> Result<MissingSourceIpPolicy, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "skip" => Ok(MissingSourceIpPolicy::Skip),
        "reject" | "fail-closed" => Ok(MissingSourceIpPolicy::Reject),
        _ => Err(ConfigError::InvalidValue(name)),
    }
}

fn parse_usize(name: &'static str, value: &str) -> Result<usize, ConfigError> {
    value
        .parse()
        .map_err(|source| ConfigError::InvalidInteger { name, source })
}

pub(super) fn client_registration_limits_from_env() -> Result<ClientRegistrationLimits, ConfigError>
{
    let limits = [
        (
            "OAUTH_CLIENT_MAX_REDIRECT_URIS",
            env::var("OAUTH_CLIENT_MAX_REDIRECT_URIS")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_REDIRECT_URIS.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH",
            env::var("OAUTH_CLIENT_MAX_REDIRECT_URI_LENGTH")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_REDIRECT_URI_LENGTH.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_SCOPES",
            env::var("OAUTH_CLIENT_MAX_SCOPES")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_SCOPES.to_string()),
        ),
        (
            "OAUTH_CLIENT_MAX_SCOPE_LENGTH",
            env::var("OAUTH_CLIENT_MAX_SCOPE_LENGTH")
                .ok()
                .unwrap_or_else(|| DEFAULT_MAX_SCOPE_LENGTH.to_string()),
        ),
    ];
    let values = limits
        .into_iter()
        .map(|(name, value)| parse_usize(name, &value))
        .collect::<Result<Vec<_>, _>>()?;
    let limits = ClientRegistrationLimits::new(values[0], values[1], values[2], values[3])
        .ok_or(ConfigError::InvalidValue("OAUTH_CLIENT_LIMITS"))?;
    let allowed_scopes = env::var("OAUTH_CLIENT_ALLOWED_SCOPES")
        .ok()
        .unwrap_or_else(|| DEFAULT_ALLOWED_SCOPES.iter().copied().collect::<Vec<_>>().join(","));
    let allowed_scopes = parse_allowed_scopes(&allowed_scopes)?;
    limits
        .with_allowed_scopes(allowed_scopes)
        .ok_or(ConfigError::InvalidValue("OAUTH_CLIENT_ALLOWED_SCOPES"))
}

fn parse_allowed_scopes(value: &str) -> Result<Vec<String>, ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue("OAUTH_CLIENT_ALLOWED_SCOPES"));
    }
    let scopes = value
        .split(',')
        .map(str::trim)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if scopes.iter().any(String::is_empty) {
        return Err(ConfigError::InvalidValue("OAUTH_CLIENT_ALLOWED_SCOPES"));
    }
    Ok(scopes)
}

/// 可配置的安全阈值与 TTL（#121）。
///
/// 这些值决定系统在暴力破解或洪泛下的行为边界，不同部署规模的合理取值差异很大。
/// 从编译期常量提升为配置项后，应急响应正在发生的攻击不再需要改代码重发版。
/// 每一项的默认值都等于提升前的硬编码值，因此不配置任何变量即保持原有行为。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecurityLimits {
    /// OAuth 公共端点按源 IP 计算的 QPS 上限。
    pub unauthenticated_source_qps: u32,
    /// 授权码有效期（秒）。RFC 6749 §4.1.2 建议不超过 10 分钟。
    pub authorization_code_ttl_seconds: u64,
    /// 待决授权请求 TTL（秒），即用户停留在授权确认页的最长时间。
    pub pending_request_ttl_seconds: u64,
    /// 单个 Client 的待决授权请求容量上限。
    pub max_pending_requests_per_client: u64,
    /// 全局待决授权请求容量上限。
    pub max_pending_requests_global: u64,
    /// 认证失败计数的固定窗口时长（秒）。
    pub auth_failure_window_seconds: i64,
    /// 单窗口内账户维度的失败次数上限。
    pub account_failure_limit: i64,
    /// 单窗口内源 IP 维度的失败次数上限。
    pub ip_failure_limit: i64,
    /// 单个 TOTP 登录 ticket 允许的累计失败次数。
    pub totp_ticket_failure_limit: i64,
    /// 外部 OAuth 登录 state 有效期（秒）。
    pub external_login_state_ttl_seconds: u64,
    /// 外部 OAuth 登录 state 的源 IP 限流窗口（秒）。
    pub external_login_state_rate_window_seconds: u64,
    /// 单窗口内单个源 IP 可创建的外部登录 state 数量上限。
    pub external_login_state_rate_limit: i64,
    /// 外部 OAuth 登录 state 的全局待决容量上限。
    pub external_login_state_max_pending: i64,
}

impl Default for SecurityLimits {
    fn default() -> Self {
        Self {
            unauthenticated_source_qps: 30,
            authorization_code_ttl_seconds: 300,
            pending_request_ttl_seconds: 600,
            max_pending_requests_per_client: 20,
            max_pending_requests_global: 1_000,
            auth_failure_window_seconds: 900,
            account_failure_limit: 10,
            ip_failure_limit: 30,
            totp_ticket_failure_limit: 5,
            external_login_state_ttl_seconds: 600,
            external_login_state_rate_window_seconds: 60,
            external_login_state_rate_limit: 30,
            external_login_state_max_pending: 10_000,
        }
    }
}

impl SecurityLimits {
    /// 校验并规整取值。**0 一律退回默认值**：QPS 为 0 表示拒绝所有请求、TTL 为 0
    /// 表示凭据签发即过期，这两者都不是任何部署想要的策略，只可能是配置错误
    /// （例如把变量设成空字符串后又被 shell 展开为 0）。静默接受会造成全站不可用，
    /// 因此这里回退并告警，而不是让服务带着自毁配置启动。
    ///
    /// 未认证来源 QPS 还设有硬上限，避免每个请求都向 Redis 滑动窗口 ZSET 追加 member，
    /// 让一个过大的阈值变成可利用的内存增长。
    ///
    /// 明显危险但仍可能是有意选择的取值（如授权码 TTL 过长）只告警，不改写。
    fn sanitized(mut self) -> Self {
        let defaults = Self::default();
        macro_rules! reset_if_zero {
            ($field:ident, $name:literal) => {
                if self.$field == 0 {
                    tracing::warn!(
                        default = defaults.$field,
                        concat!(
                            $name,
                            " is 0, which disables service; falling back to default"
                        )
                    );
                    self.$field = defaults.$field;
                }
            };
        }
        reset_if_zero!(unauthenticated_source_qps, "UNAUTHENTICATED_SOURCE_QPS");
        reset_if_zero!(
            authorization_code_ttl_seconds,
            "AUTHORIZATION_CODE_TTL_SECONDS"
        );
        reset_if_zero!(pending_request_ttl_seconds, "PENDING_REQUEST_TTL_SECONDS");
        reset_if_zero!(
            max_pending_requests_per_client,
            "MAX_PENDING_REQUESTS_PER_CLIENT"
        );
        reset_if_zero!(max_pending_requests_global, "MAX_PENDING_REQUESTS_GLOBAL");
        reset_if_zero!(
            external_login_state_ttl_seconds,
            "EXTERNAL_LOGIN_STATE_TTL_SECONDS"
        );
        reset_if_zero!(
            external_login_state_rate_window_seconds,
            "EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS"
        );

        if self.unauthenticated_source_qps > MAX_UNAUTHENTICATED_SOURCE_QPS {
            tracing::warn!(
                configured = self.unauthenticated_source_qps,
                maximum = MAX_UNAUTHENTICATED_SOURCE_QPS,
                default = defaults.unauthenticated_source_qps,
                "UNAUTHENTICATED_SOURCE_QPS exceeds the supported upper bound; falling back to default"
            );
            self.unauthenticated_source_qps = defaults.unauthenticated_source_qps;
        }

        // i64 维度同时拒绝 0 和负数：负阈值在 Redis Lua 比较里等价于「立即触发限流」。
        macro_rules! reset_if_not_positive {
            ($field:ident, $name:literal) => {
                if self.$field <= 0 {
                    tracing::warn!(
                        default = defaults.$field,
                        concat!($name, " must be positive; falling back to default")
                    );
                    self.$field = defaults.$field;
                }
            };
        }
        reset_if_not_positive!(auth_failure_window_seconds, "AUTH_FAILURE_WINDOW_SECONDS");
        reset_if_not_positive!(account_failure_limit, "ACCOUNT_FAILURE_LIMIT");
        reset_if_not_positive!(ip_failure_limit, "IP_FAILURE_LIMIT");
        reset_if_not_positive!(totp_ticket_failure_limit, "TOTP_TICKET_FAILURE_LIMIT");
        reset_if_not_positive!(
            external_login_state_rate_limit,
            "EXTERNAL_LOGIN_STATE_RATE_LIMIT"
        );
        reset_if_not_positive!(
            external_login_state_max_pending,
            "EXTERNAL_LOGIN_STATE_MAX_PENDING"
        );

        // 授权码是一次性凭据，RFC 6749 §4.1.2 建议 10 分钟以内。过长会拉长
        // 「拿到授权码但还没兑换」的攻击窗口，但确实存在慢速客户端的场景，只告警。
        if self.authorization_code_ttl_seconds > 600 {
            tracing::warn!(
                authorization_code_ttl_seconds = self.authorization_code_ttl_seconds,
                "AUTHORIZATION_CODE_TTL_SECONDS exceeds the 10 minute guidance in RFC 6749"
            );
        }
        self
    }
}

pub(super) fn security_limits_from_env() -> Result<SecurityLimits, ConfigError> {
    let defaults = SecurityLimits::default();
    Ok(SecurityLimits {
        unauthenticated_source_qps: optional_u32(
            "UNAUTHENTICATED_SOURCE_QPS",
            defaults.unauthenticated_source_qps,
        )?,
        authorization_code_ttl_seconds: optional_u64(
            "AUTHORIZATION_CODE_TTL_SECONDS",
            defaults.authorization_code_ttl_seconds,
        )?,
        pending_request_ttl_seconds: optional_u64(
            "PENDING_REQUEST_TTL_SECONDS",
            defaults.pending_request_ttl_seconds,
        )?,
        max_pending_requests_per_client: optional_u64(
            "MAX_PENDING_REQUESTS_PER_CLIENT",
            defaults.max_pending_requests_per_client,
        )?,
        max_pending_requests_global: optional_u64(
            "MAX_PENDING_REQUESTS_GLOBAL",
            defaults.max_pending_requests_global,
        )?,
        auth_failure_window_seconds: optional_i64(
            "AUTH_FAILURE_WINDOW_SECONDS",
            defaults.auth_failure_window_seconds,
        )?,
        account_failure_limit: optional_i64(
            "ACCOUNT_FAILURE_LIMIT",
            defaults.account_failure_limit,
        )?,
        ip_failure_limit: optional_i64("IP_FAILURE_LIMIT", defaults.ip_failure_limit)?,
        totp_ticket_failure_limit: optional_i64(
            "TOTP_TICKET_FAILURE_LIMIT",
            defaults.totp_ticket_failure_limit,
        )?,
        external_login_state_ttl_seconds: optional_u64(
            "EXTERNAL_LOGIN_STATE_TTL_SECONDS",
            defaults.external_login_state_ttl_seconds,
        )?,
        external_login_state_rate_window_seconds: optional_u64(
            "EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS",
            defaults.external_login_state_rate_window_seconds,
        )?,
        external_login_state_rate_limit: optional_i64(
            "EXTERNAL_LOGIN_STATE_RATE_LIMIT",
            defaults.external_login_state_rate_limit,
        )?,
        external_login_state_max_pending: optional_i64(
            "EXTERNAL_LOGIN_STATE_MAX_PENDING",
            defaults.external_login_state_max_pending,
        )?,
    }
    .sanitized())
}

#[cfg(test)]
mod tests {
    use base64::{Engine, engine::general_purpose::STANDARD};

    use super::*;

    #[test]
    fn key_ring_parser_preserves_standard_base64_padding_for_multiple_keys() {
        let current = STANDARD.encode([1_u8; 32]);
        let previous = STANDARD.encode([2_u8; 32]);
        let ring = crate::config::parse_auth_encryption_key_ring_value(
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
            let error = crate::config::parse_auth_encryption_key_ring_value(value, None)
                .expect_err("malformed key ring must be rejected");
            assert_eq!(error, ConfigError::InvalidValue("AUTH_ENCRYPTION_KEYS"));
            assert!(!error.to_string().contains("not-a-key"));
        }
    }

    /// 默认值必须等于提升为配置项之前的硬编码常量，否则升级会静默改变限流行为。
    #[test]
    fn defaults_match_the_previously_hardcoded_constants() {
        let limits = SecurityLimits::default();
        assert_eq!(limits.unauthenticated_source_qps, 30);
        assert_eq!(
            limits.authorization_code_ttl_seconds,
            crate::oauth::code::AUTHORIZATION_CODE_TTL_SECONDS
        );
        assert_eq!(
            limits.pending_request_ttl_seconds,
            crate::oauth::request_store::PENDING_REQUEST_TTL_SECONDS
        );
        assert_eq!(
            limits.max_pending_requests_per_client,
            crate::oauth::request_store::MAX_PENDING_REQUESTS_PER_CLIENT
        );
        assert_eq!(
            limits.max_pending_requests_global,
            crate::oauth::request_store::MAX_PENDING_REQUESTS_GLOBAL
        );
        assert_eq!(
            limits.auth_failure_window_seconds,
            crate::auth_limiter::domain::AUTH_FAILURE_WINDOW_SECONDS
        );
        assert_eq!(
            limits.account_failure_limit,
            crate::auth_limiter::domain::ACCOUNT_FAILURE_LIMIT
        );
        assert_eq!(
            limits.ip_failure_limit,
            crate::auth_limiter::domain::IP_FAILURE_LIMIT
        );
        assert_eq!(
            limits.totp_ticket_failure_limit,
            crate::auth_limiter::domain::TOTP_TICKET_FAILURE_LIMIT
        );
        assert_eq!(
            limits.external_login_state_ttl_seconds,
            crate::oauth::providers::state_store::EXTERNAL_LOGIN_STATE_TTL_SECONDS
        );
        assert_eq!(
            limits.external_login_state_rate_window_seconds,
            crate::oauth::providers::state_store::EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS
        );
        assert_eq!(
            limits.external_login_state_rate_limit,
            crate::oauth::providers::state_store::EXTERNAL_LOGIN_STATE_RATE_LIMIT
        );
        assert_eq!(
            limits.external_login_state_max_pending,
            crate::oauth::providers::state_store::EXTERNAL_LOGIN_STATE_MAX_PENDING
        );
    }

    /// 0 与负数是配置错误而不是安全策略，必须回退默认值，不能让服务带着自毁配置启动。
    #[test]
    fn zero_and_negative_values_fall_back_to_defaults() {
        let defaults = SecurityLimits::default();
        let sanitized = SecurityLimits {
            unauthenticated_source_qps: 0,
            authorization_code_ttl_seconds: 0,
            pending_request_ttl_seconds: 0,
            max_pending_requests_per_client: 0,
            max_pending_requests_global: 0,
            auth_failure_window_seconds: 0,
            account_failure_limit: -1,
            ip_failure_limit: 0,
            totp_ticket_failure_limit: -5,
            external_login_state_ttl_seconds: 0,
            external_login_state_rate_window_seconds: 0,
            external_login_state_rate_limit: 0,
            external_login_state_max_pending: -10,
        }
        .sanitized();
        assert_eq!(sanitized, defaults);
    }

    /// 合法的非默认取值必须原样保留，否则配置项形同虚设。
    #[test]
    fn valid_values_are_preserved() {
        let configured = SecurityLimits {
            unauthenticated_source_qps: 5,
            authorization_code_ttl_seconds: 60,
            ip_failure_limit: 100,
            ..SecurityLimits::default()
        };
        let sanitized = configured.clone().sanitized();
        assert_eq!(sanitized, configured);
    }

    /// 授权码 TTL 过长只告警、不改写：慢速客户端场景真实存在。
    #[test]
    fn long_authorization_code_ttl_is_kept_with_a_warning() {
        let sanitized = SecurityLimits {
            authorization_code_ttl_seconds: 3_600,
            ..SecurityLimits::default()
        }
        .sanitized();
        assert_eq!(sanitized.authorization_code_ttl_seconds, 3_600);
    }

    #[test]
    fn excessive_source_qps_falls_back_to_the_default() {
        let sanitized = SecurityLimits {
            unauthenticated_source_qps: MAX_UNAUTHENTICATED_SOURCE_QPS + 1,
            ..SecurityLimits::default()
        }
        .sanitized();
        assert_eq!(
            sanitized.unauthenticated_source_qps,
            SecurityLimits::default().unauthenticated_source_qps
        );
    }
}
