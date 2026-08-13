use crate::settings::{EMAIL_POLICY_KEY, EmailPolicySetting};
use crate::sqlx::PgPool;

use super::email::EmailAddress;
use super::service::UserServiceError;

/// 解析已存储的邮箱域名策略并判定单个邮箱是否放行。
///
/// 这里把"未配置"和"配置损坏"区分成两种语义，二者绝不能混为一谈：
///
/// - `None` 或空白字符串表示管理员从未写入过策略，使用 `EmailPolicySetting::default()`
///   （未启用白名单，放行）是合法的初始状态。
/// - `Some(value)` 但反序列化失败表示库里的 `setting_value` 与当前结构不兼容
///   （字段改名、类型漂移、手工改库写坏）。此时**必须 fail-closed**：
///   旧实现的 `unwrap_or_default()` 会把损坏配置静默降级为"放行一切"，
///   等于在运行期自动放宽注册域名限制，而管理员在日志和响应里都看不到异常。
///
/// 拒绝时统一返回 `EmailDomainNotAllowed`：对调用者而言判定结果就是"不允许"，
/// 具体的解析失败原因只写进日志，不进 HTTP 响应，避免泄露内部结构与配置内容。
fn evaluate_email_policy(
    raw: Option<String>,
    email: &EmailAddress,
) -> Result<(), UserServiceError> {
    let policy = match raw.filter(|value| !value.trim().is_empty()) {
        Some(value) => match serde_json::from_str::<EmailPolicySetting>(&value) {
            Ok(policy) => policy,
            Err(error) => {
                // 只记录 setting key、错误分类和位置，不记录 setting_value 全文：
                // 其中包含管理员配置的域名列表，按最小化原则不落全量日志。
                tracing::error!(
                    setting_key = EMAIL_POLICY_KEY,
                    error_line = error.line(),
                    error_column = error.column(),
                    error_classification = ?error.classify(),
                    "stored email policy is not deserializable; failing closed and rejecting registration"
                );
                return Err(UserServiceError::EmailDomainNotAllowed);
            }
        },
        None => EmailPolicySetting::default(),
    };
    if policy.allows_email(email) {
        Ok(())
    } else {
        Err(UserServiceError::EmailDomainNotAllowed)
    }
}

pub(super) async fn ensure_email_policy_allows(
    pool: &PgPool,
    email: &EmailAddress,
) -> Result<(), UserServiceError> {
    let raw = crate::sqlx::query_as::<_, (Option<String>,)>(
        "SELECT setting_value FROM app_settings WHERE setting_key = 'email_policy'",
    )
    .fetch_optional(pool)
    .await?;
    evaluate_email_policy(raw.and_then(|(value,)| value), email)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 策略判定的入参是已规范化的邮箱（Issue #302）：测试也走同一个入口，
    /// 否则会绕过被测的那条规则。
    fn email(raw: &str) -> EmailAddress {
        EmailAddress::parse(raw).unwrap_or_else(|error| panic!("{raw:?} must parse: {error}"))
    }

    fn whitelist_policy_json() -> String {
        serde_json::json!({
            "whitelist_enabled": true,
            "alias_restriction_enabled": true,
            "allowed_domains": ["corp.example"],
        })
        .to_string()
    }

    #[test]
    fn missing_setting_falls_back_to_default_and_allows() {
        // 未配置是合法初始状态，default 不启用白名单。
        assert!(evaluate_email_policy(None, &email("user@anywhere.example")).is_ok());
    }

    #[test]
    fn blank_setting_is_treated_as_unconfigured() {
        assert!(
            evaluate_email_policy(Some("   ".to_owned()), &email("user@anywhere.example")).is_ok()
        );
    }

    #[test]
    fn valid_policy_allows_whitelisted_domain() {
        assert!(
            evaluate_email_policy(Some(whitelist_policy_json()), &email("user@corp.example"))
                .is_ok()
        );
    }

    #[test]
    fn valid_policy_rejects_domain_outside_whitelist() {
        let error =
            evaluate_email_policy(Some(whitelist_policy_json()), &email("user@other.example"))
                .expect_err("domain outside the whitelist must be rejected");
        assert!(matches!(error, UserServiceError::EmailDomainNotAllowed));
    }

    #[test]
    fn valid_policy_rejects_alias_when_alias_restriction_enabled() {
        let error = evaluate_email_policy(
            Some(whitelist_policy_json()),
            &email("user+tag@corp.example"),
        )
        .expect_err("alias address must be rejected");
        assert!(matches!(error, UserServiceError::EmailDomainNotAllowed));
    }

    #[test]
    fn malformed_json_fails_closed_instead_of_using_default() {
        // 关键回归：旧实现 unwrap_or_default() 会在这里放行。
        for raw in [
            "not json at all",
            "{",
            "[]",
            r#"{"whitelist_enabled": "yes", "alias_restriction_enabled": false, "allowed_domains": []}"#,
        ] {
            let error =
                evaluate_email_policy(Some(raw.to_owned()), &email("user@anywhere.example"))
                    .expect_err("broken policy configuration must fail closed");
            assert!(
                matches!(error, UserServiceError::EmailDomainNotAllowed),
                "unexpected error for {raw:?}"
            );
        }
    }

    #[test]
    fn structural_drift_fails_closed() {
        // 字段改名 / 结构漂移：缺少必需字段时不得静默退回 default。
        let raw = serde_json::json!({ "domains": ["corp.example"] }).to_string();
        let error = evaluate_email_policy(Some(raw), &email("user@anywhere.example"))
            .expect_err("structural drift must fail closed");
        assert!(matches!(error, UserServiceError::EmailDomainNotAllowed));
    }

    #[test]
    fn rejection_error_does_not_leak_raw_configuration() {
        let raw =
            r#"{"whitelist_enabled": "SECRET-MARKER", "allowed_domains": ["internal.example"]}"#;
        let error = evaluate_email_policy(Some(raw.to_owned()), &email("user@anywhere.example"))
            .expect_err("broken policy configuration must fail closed");
        let rendered = error.to_string();
        assert!(
            !rendered.contains("SECRET-MARKER") && !rendered.contains("internal.example"),
            "error surface must not expose stored configuration: {rendered}"
        );
    }
}
