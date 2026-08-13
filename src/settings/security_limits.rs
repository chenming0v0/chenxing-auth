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
        // 取自 config/limits.rs 的 SecurityLimits::default()；
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
    /// 取值范围与 `config/limits.rs` 的 `sanitized()` 共用同一张表
    /// （`config::limit_bounds::for_each_security_limit!`），**动作**有意不同，因为
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
    /// 回退目标是调用方传入的 `defaults`，而不是结构体自身的硬编码默认。回读路径的
    /// 唯一调用方是 `SettingsService`，它把启动期环境配置（如 `ACCOUNT_FAILURE_LIMIT=50`）
    /// 当作「数据库无行时的默认值」；行存在但某项越界时回落同一来源，两路默认才不会
    /// 漂移（#361）。硬编码默认只属于 `Default`——那是环境变量本身没配时的启动值。
    /// 回退方向是收紧而非放宽，因此降级路径不会产生新的安全缺口。
    pub fn sanitized(mut self, defaults: &Self) -> Self {
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
#[path = "security_limits_tests.rs"]
mod tests;
