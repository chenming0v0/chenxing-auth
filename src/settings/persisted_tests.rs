//! 三类持久化设置共用 decode / 升级 / 校验 / 故障策略。
//!
//! Fixture 分三类：缺字段的旧 JSON、曾经合法现在越界的值、损坏文本。
//! 热路径必须 fail-closed；管理读取必须还能交出可编辑的值。

use super::*;
use crate::settings::domain::{
    PasskeyAuthenticatorAttachment, PasskeyUserVerification, SettingsValidationError,
};

const OLD_PASSKEY: &str = r#"{
    "enabled": true,
    "rp_name": "辰星认证中枢",
    "rp_id": "auth.example.com",
    "allowed_origins": "https://auth.example.com"
}"#;

const OLD_EMAIL_POLICY: &str = r#"{
    "whitelist_enabled": true,
    "allowed_domains": "corp.example"
}"#;

const OLD_SECURITY_LIMITS: &str = r#"{
    "unauthenticated_source_qps": 30,
    "authorization_code_ttl_seconds": 300,
    "account_failure_limit": 50
}"#;

const OUT_OF_RANGE_PASSKEY: &str = r#"{
    "enabled": true,
    "rp_name": "辰星认证中枢",
    "rp_id": "com",
    "user_verification": "preferred",
    "authenticator_attachment": "any",
    "allow_insecure_origin": false,
    "allowed_origins": ["https://evil.com"]
}"#;

const OUT_OF_RANGE_EMAIL_POLICY: &str = r#"{
    "whitelist_enabled": true,
    "alias_restriction_enabled": false,
    "allowed_domains": []
}"#;

const OUT_OF_RANGE_SECURITY_LIMITS: &str = r#"{
    "unauthenticated_source_qps": 30,
    "authorization_code_ttl_seconds": 86400,
    "pending_request_ttl_seconds": 600,
    "max_pending_requests_per_client": 20,
    "max_pending_requests_global": 1000,
    "auth_failure_window_seconds": 900,
    "account_failure_limit": 9223372036854775807,
    "ip_failure_limit": 0,
    "totp_ticket_failure_limit": 5,
    "external_login_state_ttl_seconds": 600,
    "external_login_state_rate_window_seconds": 60,
    "external_login_state_rate_limit": 30,
    "external_login_state_max_pending": 10000
}"#;

const CORRUPT_FIXTURES: &[&str] = &[
    "not json at all",
    "{",
    "[]",
    "null",
    "42",
    r#"{"domains":["corp.example"]}"#,
];

fn require_passkey(raw: Option<&str>) -> Result<PasskeySetting, PersistedLoadError> {
    decode_persisted(raw).require(
        PasskeySetting::default()
            .with_runtime_defaults("auth.example.com", "https://auth.example.com"),
        |value| value.with_runtime_defaults("auth.example.com", "https://auth.example.com"),
        PasskeySetting::validate,
    )
}

fn inspect_passkey(raw: Option<&str>) -> SettingInspection<PasskeySetting> {
    decode_persisted(raw).inspect(
        PasskeySetting::default()
            .with_runtime_defaults("auth.example.com", "https://auth.example.com"),
        |value| value.with_runtime_defaults("auth.example.com", "https://auth.example.com"),
        PasskeySetting::validate,
    )
}

fn require_email(raw: Option<&str>) -> Result<EmailPolicySetting, PersistedLoadError> {
    decode_persisted(raw).require(
        EmailPolicySetting::default(),
        |value| value,
        EmailPolicySetting::validate,
    )
}

fn inspect_email(raw: Option<&str>) -> SettingInspection<EmailPolicySetting> {
    decode_persisted(raw).inspect(
        EmailPolicySetting::default(),
        |value| value,
        EmailPolicySetting::validate,
    )
}

fn env_security_defaults() -> SecurityLimitsSetting {
    SecurityLimitsSetting {
        account_failure_limit: 50,
        ..SecurityLimitsSetting::default()
    }
}

fn require_limits(raw: Option<&str>) -> Result<SecurityLimitsSetting, PersistedLoadError> {
    decode_persisted(raw).require(
        env_security_defaults(),
        |value| value,
        SecurityLimitsSetting::validate,
    )
}

fn inspect_limits(raw: Option<&str>) -> SettingInspection<SecurityLimitsSetting> {
    decode_persisted(raw).inspect(
        env_security_defaults(),
        |value| value,
        SecurityLimitsSetting::validate,
    )
}

#[test]
fn old_passkey_json_upgrades_missing_fields_and_string_origins() {
    let setting = require_passkey(Some(OLD_PASSKEY)).expect("old passkey must remain usable");
    assert!(setting.enabled);
    assert_eq!(setting.rp_id, "auth.example.com");
    assert_eq!(
        setting.user_verification,
        PasskeyUserVerification::Preferred
    );
    assert_eq!(
        setting.authenticator_attachment,
        PasskeyAuthenticatorAttachment::Any
    );
    assert_eq!(
        setting.allowed_origins,
        vec!["https://auth.example.com".to_owned()]
    );
    assert!(inspect_passkey(Some(OLD_PASSKEY)).diagnostic.is_none());
}

#[test]
fn old_email_policy_json_upgrades_missing_alias_flag_and_string_domains() {
    let policy =
        require_email(Some(OLD_EMAIL_POLICY)).expect("old email policy must remain usable");
    assert!(policy.whitelist_enabled);
    assert!(!policy.alias_restriction_enabled);
    assert_eq!(policy.allowed_domains, vec!["corp.example".to_owned()]);
    assert!(inspect_email(Some(OLD_EMAIL_POLICY)).diagnostic.is_none());
}

#[test]
fn old_security_limits_json_fills_missing_fields_from_defaults() {
    let limits =
        require_limits(Some(OLD_SECURITY_LIMITS)).expect("old security limits must remain usable");
    assert_eq!(limits.unauthenticated_source_qps, 30);
    assert_eq!(limits.authorization_code_ttl_seconds, 300);
    assert_eq!(limits.account_failure_limit, 50);
    assert_eq!(
        limits.pending_request_ttl_seconds,
        SecurityLimitsSetting::default().pending_request_ttl_seconds
    );
    assert!(
        inspect_limits(Some(OLD_SECURITY_LIMITS))
            .diagnostic
            .is_none()
    );
}

#[test]
fn out_of_range_passkey_fails_closed_but_admin_can_read_the_stored_value() {
    let error = require_passkey(Some(OUT_OF_RANGE_PASSKEY))
        .expect_err("single-label rp_id must fail closed");
    assert!(matches!(
        error,
        PersistedLoadError::Invalid(SettingsValidationError::InvalidPasskeyRpId)
    ));

    let inspection = inspect_passkey(Some(OUT_OF_RANGE_PASSKEY));
    assert_eq!(inspection.value.rp_id, "com");
    assert!(matches!(
        inspection.diagnostic,
        Some(SettingDiagnostic::Invalid(
            SettingsValidationError::InvalidPasskeyRpId
        ))
    ));
}

#[test]
fn out_of_range_email_policy_fails_closed_but_admin_sees_the_empty_whitelist() {
    let error = require_email(Some(OUT_OF_RANGE_EMAIL_POLICY))
        .expect_err("enabled whitelist without domains must fail closed");
    assert!(matches!(
        error,
        PersistedLoadError::Invalid(SettingsValidationError::InvalidEmailDomain)
    ));

    let inspection = inspect_email(Some(OUT_OF_RANGE_EMAIL_POLICY));
    assert!(inspection.value.whitelist_enabled);
    assert!(inspection.value.allowed_domains.is_empty());
    assert!(matches!(
        inspection.diagnostic,
        Some(SettingDiagnostic::Invalid(
            SettingsValidationError::InvalidEmailDomain
        ))
    ));
}

#[test]
fn out_of_range_security_limits_fail_closed_instead_of_being_sanitized() {
    let error = require_limits(Some(OUT_OF_RANGE_SECURITY_LIMITS))
        .expect_err("legacy out-of-range limits must fail closed");
    assert!(matches!(
        error,
        PersistedLoadError::Invalid(SettingsValidationError::InvalidSecurityLimit(_))
    ));

    let inspection = inspect_limits(Some(OUT_OF_RANGE_SECURITY_LIMITS));
    assert_eq!(inspection.value.authorization_code_ttl_seconds, 86_400);
    assert_eq!(inspection.value.account_failure_limit, i64::MAX);
    assert_eq!(inspection.value.ip_failure_limit, 0);
    assert!(matches!(
        inspection.diagnostic,
        Some(SettingDiagnostic::Invalid(
            SettingsValidationError::InvalidSecurityLimit(_)
        ))
    ));
}

#[test]
fn corrupt_json_fails_closed_for_every_setting_and_admin_gets_defaults() {
    for raw in CORRUPT_FIXTURES {
        assert!(
            matches!(
                require_passkey(Some(raw)),
                Err(PersistedLoadError::Corrupt(_))
            ),
            "passkey {raw:?}"
        );
        assert!(
            matches!(
                require_email(Some(raw)),
                Err(PersistedLoadError::Corrupt(_))
            ),
            "email {raw:?}"
        );
        assert!(
            matches!(
                require_limits(Some(raw)),
                Err(PersistedLoadError::Corrupt(_))
            ),
            "limits {raw:?}"
        );

        let passkey = inspect_passkey(Some(raw));
        assert_eq!(passkey.diagnostic, Some(SettingDiagnostic::Corrupt));
        assert_eq!(passkey.value.rp_id, "auth.example.com");

        let email = inspect_email(Some(raw));
        assert_eq!(email.diagnostic, Some(SettingDiagnostic::Corrupt));
        assert_eq!(email.value, EmailPolicySetting::default());

        let limits = inspect_limits(Some(raw));
        assert_eq!(limits.diagnostic, Some(SettingDiagnostic::Corrupt));
        assert_eq!(limits.value, env_security_defaults());
    }
}

#[test]
fn unconfigured_uses_caller_defaults_not_hardcoded_security_limits() {
    let limits = require_limits(None).expect("missing row is a legal initial state");
    assert_eq!(limits, env_security_defaults());
    assert_ne!(
        limits.account_failure_limit,
        SecurityLimitsSetting::default().account_failure_limit
    );
    assert!(inspect_limits(None).diagnostic.is_none());
}

#[test]
fn blank_setting_is_treated_as_unconfigured() {
    assert!(require_email(Some("   ")).is_ok());
    assert!(inspect_email(Some("\n")).diagnostic.is_none());
}

#[test]
fn load_errors_do_not_embed_raw_configuration() {
    let raw = r#"{"whitelist_enabled":"SECRET-MARKER","allowed_domains":["internal.example"]}"#;
    let error = require_email(Some(raw)).expect_err("type mismatch must be corrupt");
    let rendered = error.to_string();
    assert!(
        !rendered.contains("SECRET-MARKER") && !rendered.contains("internal.example"),
        "decode error must not leak stored configuration: {rendered}"
    );
}
