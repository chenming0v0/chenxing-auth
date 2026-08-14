//! 持久化 JSON 的向后兼容 fixture（#449）。
//!
//! 字面量锁的是已经写入数据库的旧形态，不要改成「先序列化再删键」：
//! 序列化格式一变，这个回归就不再覆盖真实旧行。

use super::*;

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
