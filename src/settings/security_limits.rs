use serde::{Deserialize, Serialize};

use super::domain::SettingsValidationError;

/// 安全限流阈值配置，对应 `config::SecurityLimits` 的 13 个字段。
/// 字段类型与默认值必须与 `SecurityLimits` 保持一致，否则升级会静默改变限流行为。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityLimitsSetting {
    pub unauthenticated_source_qps: u32,
    pub authorization_code_ttl_seconds: u64,
    pub pending_request_ttl_seconds: u64,
    pub max_pending_requests_per_client: u64,
    pub max_pending_requests_global: u64,
    pub auth_failure_window_seconds: i64,
    pub account_failure_limit: i64,
    pub ip_failure_limit: i64,
    pub totp_ticket_failure_limit: i64,
    pub external_login_state_ttl_seconds: u64,
    pub external_login_state_rate_window_seconds: u64,
    pub external_login_state_rate_limit: i64,
    pub external_login_state_max_pending: i64,
}

impl Default for SecurityLimitsSetting {
    fn default() -> Self {
        // 取自 config_limits.rs 的 SecurityLimits::default()；
        // security_limits_default_matches_config_limits 测试守住两处不漂移。
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

impl From<&crate::config::SecurityLimits> for SecurityLimitsSetting {
    fn from(value: &crate::config::SecurityLimits) -> Self {
        Self {
            unauthenticated_source_qps: value.unauthenticated_source_qps,
            authorization_code_ttl_seconds: value.authorization_code_ttl_seconds,
            pending_request_ttl_seconds: value.pending_request_ttl_seconds,
            max_pending_requests_per_client: value.max_pending_requests_per_client,
            max_pending_requests_global: value.max_pending_requests_global,
            auth_failure_window_seconds: value.auth_failure_window_seconds,
            account_failure_limit: value.account_failure_limit,
            ip_failure_limit: value.ip_failure_limit,
            totp_ticket_failure_limit: value.totp_ticket_failure_limit,
            external_login_state_ttl_seconds: value.external_login_state_ttl_seconds,
            external_login_state_rate_window_seconds: value
                .external_login_state_rate_window_seconds,
            external_login_state_rate_limit: value.external_login_state_rate_limit,
            external_login_state_max_pending: value.external_login_state_max_pending,
        }
    }
}

impl SecurityLimitsSetting {
    /// 校验语义与 `config_limits.rs` 的 `sanitized()` **有意不同**，原因是输入来源不同：
    ///
    /// - 环境变量是启动期输入，此时没有人能看到错误提示。非法值只能回退默认，
    ///   否则服务会带着自毁配置起不来，运维还得先猜是哪个变量写错了。
    /// - 管理 API 是交互式输入，管理员正等着响应。非法值必须报错让他知道改哪一项，
    ///   静默改写会让人以为已经生效，等到真被攻击时才发现阈值根本不是自己设的。
    ///
    /// u32/u64 字段 `== 0` 拒绝：QPS 为 0 表示拒绝所有请求、TTL 为 0 表示凭据签发即过期。
    /// i64 字段 `<= 0` 拒绝：负阈值在 Redis Lua 比较里等价于「立即触发限流」。
    ///
    /// 错误里带字段名，供 UI 提示具体是哪一项非法。
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        // u32/u64 与 i64 的边界不同，但拒绝动作一致，用同一个宏按比较表达式区分。
        macro_rules! reject {
            ($($field:ident: $invalid:expr),+ $(,)?) => {
                $(
                    if $invalid(self.$field) {
                        return Err(SettingsValidationError::InvalidSecurityLimit(
                            stringify!($field),
                        ));
                    }
                )+
            };
        }
        let is_zero_u32 = |value: u32| value == 0;
        let is_zero_u64 = |value: u64| value == 0;
        let is_not_positive = |value: i64| value <= 0;

        reject! {
            unauthenticated_source_qps: is_zero_u32,
            authorization_code_ttl_seconds: is_zero_u64,
            pending_request_ttl_seconds: is_zero_u64,
            max_pending_requests_per_client: is_zero_u64,
            max_pending_requests_global: is_zero_u64,
            auth_failure_window_seconds: is_not_positive,
            account_failure_limit: is_not_positive,
            ip_failure_limit: is_not_positive,
            totp_ticket_failure_limit: is_not_positive,
            external_login_state_ttl_seconds: is_zero_u64,
            external_login_state_rate_window_seconds: is_zero_u64,
            external_login_state_rate_limit: is_not_positive,
            external_login_state_max_pending: is_not_positive,
        }

        // 授权码是一次性凭据，RFC 6749 §4.1.2 建议 10 分钟以内。过长会拉长
        // 「拿到授权码但还没兑换」的攻击窗口，但慢速客户端场景真实存在，只告警。
        if self.authorization_code_ttl_seconds > 600 {
            tracing::warn!(
                authorization_code_ttl_seconds = self.authorization_code_ttl_seconds,
                "authorization_code_ttl_seconds exceeds the 10 minute guidance in RFC 6749 §4.1.2"
            );
        }

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 默认值必须逐字段等于 `config::SecurityLimits`，否则两处会各自漂移。
    #[test]
    fn security_limits_default_matches_config_limits() {
        let setting = SecurityLimitsSetting::default();
        let config = crate::config::SecurityLimits::default();
        assert_eq!(
            setting.unauthenticated_source_qps,
            config.unauthenticated_source_qps
        );
        assert_eq!(
            setting.authorization_code_ttl_seconds,
            config.authorization_code_ttl_seconds
        );
        assert_eq!(
            setting.pending_request_ttl_seconds,
            config.pending_request_ttl_seconds
        );
        assert_eq!(
            setting.max_pending_requests_per_client,
            config.max_pending_requests_per_client
        );
        assert_eq!(
            setting.max_pending_requests_global,
            config.max_pending_requests_global
        );
        assert_eq!(
            setting.auth_failure_window_seconds,
            config.auth_failure_window_seconds
        );
        assert_eq!(setting.account_failure_limit, config.account_failure_limit);
        assert_eq!(setting.ip_failure_limit, config.ip_failure_limit);
        assert_eq!(
            setting.totp_ticket_failure_limit,
            config.totp_ticket_failure_limit
        );
        assert_eq!(
            setting.external_login_state_ttl_seconds,
            config.external_login_state_ttl_seconds
        );
        assert_eq!(
            setting.external_login_state_rate_window_seconds,
            config.external_login_state_rate_window_seconds
        );
        assert_eq!(
            setting.external_login_state_rate_limit,
            config.external_login_state_rate_limit
        );
        assert_eq!(
            setting.external_login_state_max_pending,
            config.external_login_state_max_pending
        );
    }

    /// 与启动期解析不同，管理 API 必须拒绝并指出字段名，不能静默回退默认。
    #[test]
    fn security_limits_rejects_zero_and_negative_with_field_name() {
        let cases: Vec<(SecurityLimitsSetting, &'static str)> = vec![
            (
                SecurityLimitsSetting {
                    unauthenticated_source_qps: 0,
                    ..Default::default()
                },
                "unauthenticated_source_qps",
            ),
            (
                SecurityLimitsSetting {
                    authorization_code_ttl_seconds: 0,
                    ..Default::default()
                },
                "authorization_code_ttl_seconds",
            ),
            (
                SecurityLimitsSetting {
                    pending_request_ttl_seconds: 0,
                    ..Default::default()
                },
                "pending_request_ttl_seconds",
            ),
            (
                SecurityLimitsSetting {
                    max_pending_requests_per_client: 0,
                    ..Default::default()
                },
                "max_pending_requests_per_client",
            ),
            (
                SecurityLimitsSetting {
                    max_pending_requests_global: 0,
                    ..Default::default()
                },
                "max_pending_requests_global",
            ),
            (
                SecurityLimitsSetting {
                    auth_failure_window_seconds: 0,
                    ..Default::default()
                },
                "auth_failure_window_seconds",
            ),
            (
                SecurityLimitsSetting {
                    account_failure_limit: -1,
                    ..Default::default()
                },
                "account_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    ip_failure_limit: 0,
                    ..Default::default()
                },
                "ip_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    totp_ticket_failure_limit: -5,
                    ..Default::default()
                },
                "totp_ticket_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    external_login_state_ttl_seconds: 0,
                    ..Default::default()
                },
                "external_login_state_ttl_seconds",
            ),
            (
                SecurityLimitsSetting {
                    external_login_state_rate_window_seconds: 0,
                    ..Default::default()
                },
                "external_login_state_rate_window_seconds",
            ),
            (
                SecurityLimitsSetting {
                    external_login_state_rate_limit: 0,
                    ..Default::default()
                },
                "external_login_state_rate_limit",
            ),
            (
                SecurityLimitsSetting {
                    external_login_state_max_pending: -10,
                    ..Default::default()
                },
                "external_login_state_max_pending",
            ),
        ];

        for (invalid, field) in cases {
            assert_eq!(
                invalid.validate().expect_err("must be rejected"),
                SettingsValidationError::InvalidSecurityLimit(field),
                "expected {field} to be rejected"
            );
        }
    }

    /// 合法的非默认取值必须原样保留，否则配置项形同虚设。
    #[test]
    fn security_limits_preserves_valid_nondefault_values() {
        let configured = SecurityLimitsSetting {
            unauthenticated_source_qps: 5,
            authorization_code_ttl_seconds: 60,
            ip_failure_limit: 100,
            ..Default::default()
        };
        let validated = configured.clone().validate().expect("valid values");
        assert_eq!(validated, configured);
    }

    /// 授权码 TTL 过长只告警、不拒绝：与 `sanitized()` 的 RFC 6749 策略保持一致。
    #[test]
    fn security_limits_accepts_long_authorization_code_ttl_with_a_warning() {
        let validated = SecurityLimitsSetting {
            authorization_code_ttl_seconds: 3_600,
            ..Default::default()
        }
        .validate()
        .expect("long ttl only warns");
        assert_eq!(validated.authorization_code_ttl_seconds, 3_600);
    }
}
