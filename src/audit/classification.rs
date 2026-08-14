//! 用户安全事件的分级体系（Issue #308）。
//!
//! 每个事件两个正交维度，由服务端直接返回，前端不维护 action 白名单：
//!
//! - **category**（类别，用于列表筛选）：`auth` / `session` / `authorization` /
//!   `account`；
//! - **severity**（等级，用于呈现与告警）：`info` / `notice` / `warning` /
//!   `critical`。
//!
//! action → (category, severity) 的映射只在这里定义一次，列表与详情接口共用。
//! 未映射的 action 回落到 `account` / `info`，不 panic、不丢事件——新增 action 时
//! 在这里补一行，而不是在接口层维护第二份映射。

use serde::Serialize;

/// 安全事件的类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventCategory {
    /// 登录与认证因子活动。
    Auth,
    /// 会话生命周期变更。
    Session,
    /// OAuth 授权相关活动。
    Authorization,
    /// 账户资料与凭据变更。
    Account,
}

/// 安全事件的等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventSeverity {
    /// 常规活动。
    Info,
    /// 成功的敏感操作。
    Notice,
    /// 需要用户留意。
    Warning,
    /// 高危变更。
    Critical,
}

/// action → (category, severity) 的单点映射（Issue #308）。
///
/// 表项覆盖当前代码库实际发出的事件，以及提案约定的 action 名（`login_failed`、
/// `oauth_consent`、`oauth_consent_revoke`、`password_change`），后两者为尚未落库
/// 的契约预留。新增 action 时必须在这里补一行；未映射的 action 回落到
/// `account` / `info`，保证列表与详情不会 panic 或丢事件。
pub fn classify(action: &str) -> (SecurityEventCategory, SecurityEventSeverity) {
    match action {
        // auth：登录与认证因子
        "login" => (SecurityEventCategory::Auth, SecurityEventSeverity::Notice),
        "login_failure"
        | "login_failed"
        | "mfa_failure"
        | "rate_limit_triggered"
        | "passkey_recovery_required"
        | "auth_factor_key_unavailable" => {
            (SecurityEventCategory::Auth, SecurityEventSeverity::Warning)
        }
        // session：会话生命周期
        "session_revoke" => (
            SecurityEventCategory::Session,
            SecurityEventSeverity::Warning,
        ),
        // authorization：OAuth 授权
        "oauth_consent" | "authorization_code_issue" => (
            SecurityEventCategory::Authorization,
            SecurityEventSeverity::Notice,
        ),
        "consent_revoke" | "oauth_consent_revoke" | "authorization_request_rebound" => (
            SecurityEventCategory::Authorization,
            SecurityEventSeverity::Warning,
        ),
        "authorization_denied" => (
            SecurityEventCategory::Authorization,
            SecurityEventSeverity::Info,
        ),
        // account：资料与凭据变更
        "password_change" | "user_totp_factor_reset" | "user_passkey_factor_reset" => (
            SecurityEventCategory::Account,
            SecurityEventSeverity::Critical,
        ),
        "user_avatar_update" | "user_avatar_remove" => {
            (SecurityEventCategory::Account, SecurityEventSeverity::Info)
        }
        // 未映射：默认 account/info，不 panic 不丢事件
        _ => (SecurityEventCategory::Account, SecurityEventSeverity::Info),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_actions_classify_into_their_documented_quadrant() {
        assert_eq!(
            classify("login"),
            (SecurityEventCategory::Auth, SecurityEventSeverity::Notice)
        );
        assert_eq!(
            classify("login_failure"),
            (SecurityEventCategory::Auth, SecurityEventSeverity::Warning)
        );
        assert_eq!(
            classify("session_revoke"),
            (
                SecurityEventCategory::Session,
                SecurityEventSeverity::Warning
            )
        );
        assert_eq!(
            classify("oauth_consent"),
            (
                SecurityEventCategory::Authorization,
                SecurityEventSeverity::Notice
            )
        );
        assert_eq!(
            classify("consent_revoke"),
            (
                SecurityEventCategory::Authorization,
                SecurityEventSeverity::Warning
            )
        );
        assert_eq!(
            classify("password_change"),
            (
                SecurityEventCategory::Account,
                SecurityEventSeverity::Critical
            )
        );
        assert_eq!(
            classify("user_passkey_factor_reset"),
            (
                SecurityEventCategory::Account,
                SecurityEventSeverity::Critical
            )
        );
        assert_eq!(
            classify("user_totp_factor_reset"),
            (
                SecurityEventCategory::Account,
                SecurityEventSeverity::Critical
            )
        );
        assert_eq!(
            classify("user_avatar_update"),
            (SecurityEventCategory::Account, SecurityEventSeverity::Info)
        );
    }

    /// 未映射的 action 必须回落默认值，而不是让接口 panic 或丢事件（提案硬性要求）。
    #[test]
    fn unknown_actions_fall_back_to_account_info() {
        assert_eq!(
            classify("some_future_action"),
            (SecurityEventCategory::Account, SecurityEventSeverity::Info)
        );
        assert_eq!(
            classify(""),
            (SecurityEventCategory::Account, SecurityEventSeverity::Info)
        );
    }
}
