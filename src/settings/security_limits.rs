use serde::{Deserialize, Serialize};

use crate::config::for_each_security_limit;

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
    /// 校验管理 API 写入的取值：越界即拒绝，并回报越界的字段名。
    ///
    /// 取值范围与 `config_limits.rs` 的 `sanitized()` 共用同一张表
    /// （`config_limit_bounds::for_each_security_limit!`），**动作**有意不同，因为
    /// 输入来源不同：
    ///
    /// - 环境变量是启动期输入，此时没有人能看到错误提示。非法值只能回退默认，
    ///   否则服务会带着自毁配置起不来，运维还得先猜是哪个变量写错了。
    /// - 管理 API 是交互式输入，管理员正等着响应。非法值必须报错让他知道改哪一项，
    ///   静默改写会让人以为已经生效，等到真被攻击时才发现阈值根本不是自己设的。
    ///
    /// 下界统一是 1：QPS 为 0 表示拒绝所有请求、TTL 为 0 表示凭据签发即过期，
    /// i64 阈值 `<= 0` 在 Redis Lua 比较里等价于「立即触发限流」。
    ///
    /// 上界同样必须拒绝：阈值本身就是安全控制，`account_failure_limit = i64::MAX`
    /// 等于关掉账户锁定，而 UI 上看不出任何异常（#260）。
    pub fn validate(self) -> Result<Self, SettingsValidationError> {
        // 下界统一是 1，故 `< 1` 同时覆盖无符号的 0 与有符号的非正数。
        macro_rules! reject_if_out_of_range {
            ($field:ident, $max:expr, $env:literal) => {
                if self.$field < 1 || self.$field > $max {
                    return Err(SettingsValidationError::InvalidSecurityLimit(stringify!(
                        $field
                    )));
                }
            };
        }
        for_each_security_limit!(reject_if_out_of_range);

        Ok(self)
    }

    /// 回读已持久化的取值时使用：越界项回退默认值并告警，不返回错误。
    ///
    /// 与 `validate()` 的差别只在动作，原因同样是输入来源——这里的输入是数据库里
    /// 已经存在的行，可能是在上界收紧之前写入的合法值。回读路径被 OAuth 授权、
    /// 令牌签发和失败限流器共用（9 个调用点），一旦返回错误，限流器按失败策略
    /// 关闭、授权端点直接 500，等于让一条陈旧配置把整套协议流程打死；而且管理员
    /// 连设置页都打不开，无法自行改回来。
    ///
    /// 回退方向是收紧而非放宽，因此降级路径不会产生新的安全缺口。
    pub fn sanitized(mut self) -> Self {
        let defaults = Self::default();
        macro_rules! reset_if_out_of_range {
            ($field:ident, $max:expr, $env:literal) => {
                if self.$field < 1 || self.$field > $max {
                    tracing::warn!(
                        configured = self.$field,
                        maximum = $max,
                        default = defaults.$field,
                        concat!(
                            "stored security limit ",
                            stringify!($field),
                            " is outside the supported range; falling back to default"
                        )
                    );
                    self.$field = defaults.$field;
                }
            };
        }
        for_each_security_limit!(reset_if_out_of_range);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // 生产代码里 `for_each_security_limit!` 用绝对路径引用上界常量；测试要按名字断言。
    use crate::config::MAX_AUTHORIZATION_CODE_TTL_SECONDS;

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

    /// #260：每一项都必须有上界。逐字段把值设成 `上界 + 1`，确认拒绝的是这一项，
    /// 漏掉任何字段这个用例都会失败。
    #[test]
    fn security_limits_rejects_every_value_above_its_upper_bound() {
        macro_rules! assert_rejects_above_bound {
            ($field:ident, $max:expr, $env:literal) => {{
                let invalid = SecurityLimitsSetting {
                    $field: $max + 1,
                    ..Default::default()
                };
                assert_eq!(
                    invalid.validate().expect_err(concat!(
                        stringify!($field),
                        " above its upper bound must be rejected"
                    )),
                    SettingsValidationError::InvalidSecurityLimit(stringify!($field))
                );

                // 恰好等于上界必须接受，否则上界会把边界值一起误杀。
                let boundary = SecurityLimitsSetting {
                    $field: $max,
                    ..Default::default()
                };
                assert_eq!(
                    boundary.clone().validate().expect(concat!(
                        stringify!($field),
                        " at its bound must be accepted"
                    )),
                    boundary
                );
            }};
        }
        for_each_security_limit!(assert_rejects_above_bound);
    }

    /// 饱和取值是 #260 报告的原始利用手法：`i64::MAX` 让账户锁定永不触发。
    #[test]
    fn security_limits_rejects_saturated_values() {
        let cases: Vec<(SecurityLimitsSetting, &'static str)> = vec![
            (
                SecurityLimitsSetting {
                    account_failure_limit: i64::MAX,
                    ..Default::default()
                },
                "account_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    ip_failure_limit: i64::MAX,
                    ..Default::default()
                },
                "ip_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    totp_ticket_failure_limit: i64::MAX,
                    ..Default::default()
                },
                "totp_ticket_failure_limit",
            ),
            (
                SecurityLimitsSetting {
                    max_pending_requests_per_client: u64::MAX,
                    ..Default::default()
                },
                "max_pending_requests_per_client",
            ),
            (
                SecurityLimitsSetting {
                    max_pending_requests_global: u64::MAX,
                    ..Default::default()
                },
                "max_pending_requests_global",
            ),
            (
                SecurityLimitsSetting {
                    authorization_code_ttl_seconds: u64::MAX,
                    ..Default::default()
                },
                "authorization_code_ttl_seconds",
            ),
        ];

        for (invalid, field) in cases {
            assert_eq!(
                invalid.validate().expect_err("must be rejected"),
                SettingsValidationError::InvalidSecurityLimit(field),
                "expected saturated {field} to be rejected"
            );
        }
    }

    /// 默认值必须落在自己的上下界之内，否则默认配置会被自己的校验拒绝。
    #[test]
    fn security_limits_default_passes_validation() {
        let defaults = SecurityLimitsSetting::default();
        assert_eq!(
            defaults.clone().validate().expect("default must be valid"),
            defaults
        );
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

    /// 授权码 TTL 曾经「过长只告警、不拒绝」。#260 起改为硬上界：授权码是一次性
    /// 凭据，兑换由客户端后端立即发起，超过 RFC 6749 §4.1.2 的 10 分钟只会拉长
    /// 「已泄露但尚未兑换」的攻击窗口。
    #[test]
    fn security_limits_rejects_authorization_code_ttl_beyond_the_rfc_guidance() {
        let invalid = SecurityLimitsSetting {
            authorization_code_ttl_seconds: 3_600,
            ..Default::default()
        };
        assert_eq!(
            invalid
                .validate()
                .expect_err("ttl beyond the RFC guidance must be rejected"),
            SettingsValidationError::InvalidSecurityLimit("authorization_code_ttl_seconds")
        );

        // 600 是 RFC 建议的边界值本身，必须仍然可配。
        let boundary = SecurityLimitsSetting {
            authorization_code_ttl_seconds: MAX_AUTHORIZATION_CODE_TTL_SECONDS,
            ..Default::default()
        };
        assert_eq!(
            boundary.clone().validate().expect("the bound itself is ok"),
            boundary
        );
    }

    /// 回读路径必须降级而不是报错：上界收紧之前写入的旧行不能把 OAuth 流程打死。
    #[test]
    fn security_limits_sanitized_falls_back_out_of_range_stored_values() {
        let defaults = SecurityLimitsSetting::default();
        let sanitized = SecurityLimitsSetting {
            account_failure_limit: i64::MAX,
            authorization_code_ttl_seconds: 86_400,
            ip_failure_limit: 0,
            ..Default::default()
        }
        .sanitized();

        assert_eq!(sanitized, defaults);
        // 降级后的取值必须自身合法，否则回读结果仍然是不可用配置。
        assert_eq!(
            sanitized
                .clone()
                .validate()
                .expect("sanitized must be valid"),
            sanitized
        );
    }

    /// 合法的已持久化取值不能被回读路径改写，否则管理员保存的配置形同虚设。
    #[test]
    fn security_limits_sanitized_preserves_valid_stored_values() {
        let stored = SecurityLimitsSetting {
            unauthenticated_source_qps: 5,
            authorization_code_ttl_seconds: 60,
            ip_failure_limit: 100,
            ..Default::default()
        };
        assert_eq!(stored.clone().sanitized(), stored);
    }
}
