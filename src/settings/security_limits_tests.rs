//! [`SecurityLimitsSetting`] 的写入校验测试。
//!
//! 已持久化值的 decode / 旧 schema / 越界 fail-closed / 管理读取诊断在
//! `persisted_tests.rs`。这里只守「管理 API 拒绝越界并指出字段名」。

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
