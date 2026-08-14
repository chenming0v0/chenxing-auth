//! 持久化 JSON 的向后兼容 fixture（#449）。
//!
//! 字面量锁的是已经写入数据库的旧形态，不要改成「先序列化再删键」：
//! 序列化格式一变，这个回归就不再覆盖真实旧行。

use super::*;
use crate::settings::domain::SettingsValidationError;

/// 8f0f28a 起写入的完整 Passkey 行。
const LEGACY_PASSKEY: &str = r#"{
    "enabled": true,
    "rp_name": "辰星认证中枢",
    "rp_id": "auth.clya.top",
    "user_verification": "preferred",
    "authenticator_attachment": "any",
    "allow_insecure_origin": false,
    "allowed_origins": ["https://auth.clya.top"]
}"#;

/// 管理员曾显式放行明文 origin 的旧行：升级后必须原样保留，不能被 default 改回 false。
const LEGACY_PASSKEY_INSECURE: &str = r#"{
    "enabled": true,
    "rp_name": "辰星认证中枢",
    "rp_id": "auth.clya.top",
    "user_verification": "required",
    "authenticator_attachment": "platform",
    "allow_insecure_origin": true,
    "allowed_origins": ["http://auth.clya.top"]
}"#;

/// 8f0f28a 起写入的完整邮箱策略行。
const LEGACY_EMAIL_POLICY: &str = r#"{
    "whitelist_enabled": true,
    "alias_restriction_enabled": true,
    "allowed_domains": ["corp.example"]
}"#;

/// bfd6b4e 起写入的完整安全阈值行，含若干非默认取值。
const LEGACY_SECURITY_LIMITS: &str = r#"{
    "unauthenticated_source_qps": 5,
    "authorization_code_ttl_seconds": 60,
    "pending_request_ttl_seconds": 600,
    "max_pending_requests_per_client": 20,
    "max_pending_requests_global": 1000,
    "auth_failure_window_seconds": 900,
    "account_failure_limit": 3,
    "ip_failure_limit": 100,
    "totp_ticket_failure_limit": 5,
    "external_login_state_ttl_seconds": 600,
    "external_login_state_rate_window_seconds": 60,
    "external_login_state_rate_limit": 30,
    "external_login_state_max_pending": 10000
}"#;

#[test]
fn legacy_passkey_fixture_remains_readable() {
    let setting = parse_passkey(LEGACY_PASSKEY).expect("legacy passkey fixture");
    assert!(setting.enabled);
    assert_eq!(setting.rp_id, "auth.clya.top");
    assert!(!setting.allow_insecure_origin);
    assert_eq!(
        setting.allowed_origins,
        vec!["https://auth.clya.top".to_owned()]
    );
}

#[test]
fn passkey_missing_allow_insecure_origin_stays_false() {
    let raw = r#"{
        "enabled": true,
        "rp_name": "辰星认证中枢",
        "rp_id": "auth.clya.top",
        "user_verification": "preferred",
        "authenticator_attachment": "any",
        "allowed_origins": ["https://auth.clya.top"]
    }"#;
    let setting = parse_passkey(raw).expect("missing insecure flag must default closed");
    assert!(!setting.allow_insecure_origin);
}

#[test]
fn passkey_preserves_explicit_insecure_origin() {
    let setting = parse_passkey(LEGACY_PASSKEY_INSECURE).expect("insecure fixture");
    assert!(setting.allow_insecure_origin);
    assert_eq!(
        setting.user_verification,
        crate::settings::PasskeyUserVerification::Required
    );
}

#[test]
fn passkey_missing_rp_name_uses_default_without_touching_other_fields() {
    let raw = r#"{
        "enabled": false,
        "rp_id": "auth.clya.top",
        "user_verification": "preferred",
        "authenticator_attachment": "any",
        "allow_insecure_origin": false,
        "allowed_origins": ["https://auth.clya.top"]
    }"#;
    let setting = parse_passkey(raw).expect("missing rp_name");
    assert!(!setting.enabled);
    assert_eq!(setting.rp_name, PasskeySetting::default().rp_name);
    assert_eq!(setting.rp_id, "auth.clya.top");
}

#[test]
fn admin_api_passkey_still_rejects_partial_documents() {
    let partial = r#"{"enabled": true, "rp_id": "auth.clya.top"}"#;
    assert!(
        serde_json::from_str::<PasskeySetting>(partial).is_err(),
        "admin PUT must not silently fill defaults"
    );
    assert!(parse_passkey(partial).is_ok());
}

#[test]
fn legacy_email_policy_fixture_remains_readable() {
    let policy = parse_email_policy(LEGACY_EMAIL_POLICY).expect("legacy email policy fixture");
    assert!(policy.whitelist_enabled);
    assert!(policy.alias_restriction_enabled);
    assert_eq!(policy.allowed_domains, vec!["corp.example".to_owned()]);
}

#[test]
fn email_policy_missing_alias_flag_keeps_whitelist_closed() {
    let raw = r#"{
        "whitelist_enabled": true,
        "allowed_domains": ["corp.example"]
    }"#;
    let policy = parse_email_policy(raw).expect("missing alias flag");
    assert!(policy.whitelist_enabled);
    assert!(!policy.alias_restriction_enabled);
    assert_eq!(policy.allowed_domains, vec!["corp.example".to_owned()]);
    let allowed =
        crate::users::email::EmailAddress::parse("user@corp.example").expect("fixture email");
    let rejected =
        crate::users::email::EmailAddress::parse("user@other.example").expect("fixture email");
    assert!(policy.allows_email(&allowed));
    assert!(!policy.allows_email(&rejected));
}

#[test]
fn email_policy_missing_whitelist_flag_is_rejected() {
    for raw in [
        "{}",
        r#"{"alias_restriction_enabled": true, "allowed_domains": ["corp.example"]}"#,
        r#"{"domains": ["corp.example"]}"#,
    ] {
        parse_email_policy(raw).expect_err("missing whitelist_enabled must fail closed");
    }
}

#[test]
fn admin_api_email_policy_still_rejects_partial_documents() {
    let partial = r#"{"whitelist_enabled": true, "allowed_domains": ["corp.example"]}"#;
    assert!(
        serde_json::from_str::<EmailPolicySetting>(partial).is_err(),
        "admin PUT must not silently fill defaults"
    );
    assert!(parse_email_policy(partial).is_ok());
}

#[test]
fn legacy_security_limits_fixture_remains_readable() {
    let limits = parse_security_limits(LEGACY_SECURITY_LIMITS).expect("legacy limits fixture");
    assert_eq!(limits.unauthenticated_source_qps, 5);
    assert_eq!(limits.authorization_code_ttl_seconds, 60);
    assert_eq!(limits.account_failure_limit, 3);
    assert_eq!(limits.ip_failure_limit, 100);
}

#[test]
fn security_limits_missing_field_uses_safe_default_not_zero() {
    let raw = r#"{
        "unauthenticated_source_qps": 5,
        "authorization_code_ttl_seconds": 60,
        "pending_request_ttl_seconds": 600,
        "max_pending_requests_per_client": 20,
        "max_pending_requests_global": 1000,
        "auth_failure_window_seconds": 900,
        "ip_failure_limit": 100,
        "totp_ticket_failure_limit": 5,
        "external_login_state_ttl_seconds": 600,
        "external_login_state_rate_window_seconds": 60,
        "external_login_state_rate_limit": 30,
        "external_login_state_max_pending": 10000
    }"#;
    let limits = parse_security_limits(raw).expect("missing account_failure_limit");
    assert_eq!(
        limits.account_failure_limit,
        SecurityLimitsSetting::default().account_failure_limit
    );
    assert_ne!(limits.account_failure_limit, 0);
    assert_eq!(limits.unauthenticated_source_qps, 5);
    assert_eq!(limits.ip_failure_limit, 100);
}

#[test]
fn security_limits_empty_object_uses_full_defaults_not_zeros() {
    let limits = parse_security_limits("{}").expect("empty object");
    assert_eq!(limits, SecurityLimitsSetting::default());
    assert_ne!(limits.account_failure_limit, 0);
    assert_ne!(limits.unauthenticated_source_qps, 0);
}

#[test]
fn admin_api_security_limits_still_rejects_partial_documents() {
    let partial = r#"{"account_failure_limit": 3}"#;
    assert!(
        serde_json::from_str::<SecurityLimitsSetting>(partial).is_err(),
        "admin PUT must not silently reset omitted limits to defaults"
    );
    let parsed = parse_security_limits(partial).expect("persisted partial");
    assert_eq!(parsed.account_failure_limit, 3);
}

#[test]
fn non_object_payloads_are_rejected() {
    for raw in ["[]", "null", "\"passkey\"", "0"] {
        parse_passkey(raw).expect_err(raw);
        parse_email_policy(raw).expect_err(raw);
        parse_security_limits(raw).expect_err(raw);
    }
}

// --- #448：热路径 fail-closed / 管理读取可修复诊断 ---

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

const CORRUPT_FIXTURES: &[&str] = &["not json at all", "{", "[]", "null", "42"];

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
fn load_errors_do_not_embed_raw_configuration() {
    let raw = r#"{"whitelist_enabled":"SECRET-MARKER","allowed_domains":["internal.example"]}"#;
    let error = require_email(Some(raw)).expect_err("type mismatch must be corrupt");
    let rendered = error.to_string();
    assert!(
        !rendered.contains("SECRET-MARKER") && !rendered.contains("internal.example"),
        "decode error must not leak stored configuration: {rendered}"
    );
}
