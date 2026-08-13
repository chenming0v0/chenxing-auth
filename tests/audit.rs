use std::time::Duration;

use chenxing_auth::audit::{AuditError, AuditEvent, AuditService, stable_account_reference};

#[test]
fn audit_event_redacts_sensitive_values_from_metadata() {
    let event = AuditEvent::new(
        "user".to_owned(),
        Some("1".to_owned()),
        "login".to_owned(),
        "session".to_owned(),
        Some("session-1".to_owned()),
        serde_json::json!({"password": "do-not-store", "result": "success"}),
    );

    assert!(event.metadata.get("password").is_none());
    assert_eq!(event.metadata["result"], "success");
}

#[test]
fn token_revoke_keeps_non_secret_token_type_metadata() {
    let event = AuditEvent::new(
        "oauth_client".to_owned(),
        None,
        "token_revoke".to_owned(),
        "oauth_token".to_owned(),
        Some("client-1".to_owned()),
        serde_json::json!({"token_type": "refresh_token", "result": "success"}),
    );

    assert_eq!(event.action, "token_revoke");
    assert_eq!(event.metadata["token_type"], "refresh_token");
    assert_eq!(event.metadata["result"], "success");
}

#[test]
fn audit_event_redacts_nested_and_variant_sensitive_values() {
    let event = AuditEvent::new(
        "user".to_owned(),
        Some("1".to_owned()),
        "token_refresh".to_owned(),
        "oauth_client".to_owned(),
        Some("client-1".to_owned()),
        serde_json::json!({
            "safe": "retained",
            "nested": {
                "passwordHash": "hidden-password",
                "details": [{
                    "code_verifier": "hidden-verifier",
                    "visible": true
                }]
            },
            "credentials": {"unknown_secret_value": "hidden-credential"},
            "totp_secret": "hidden-totp",
            "refreshToken": "hidden-refresh",
            "token_count": 3,
            "token_type": "Bearer",
            "token_type_hint": "refresh_token",
            "password_configured": true
        }),
    );

    let serialized = serde_json::to_string(&event.metadata).expect("metadata serializes");
    for secret in [
        "hidden-password",
        "hidden-verifier",
        "hidden-credential",
        "hidden-totp",
        "hidden-refresh",
    ] {
        assert!(!serialized.contains(secret));
    }
    assert_eq!(event.metadata["safe"], "retained");
    assert_eq!(event.metadata["nested"]["details"][0]["visible"], true);
    assert!(event.metadata.get("credentials").is_none());
    assert_eq!(event.metadata["token_count"], 3);
    assert_eq!(event.metadata["token_type"], "Bearer");
    assert_eq!(event.metadata["token_type_hint"], "refresh_token");
    assert_eq!(event.metadata["password_configured"], true);
}

#[test]
fn audit_event_redacts_exact_credential_keys_without_substring_false_positives() {
    let event = AuditEvent::new(
        "system".to_owned(),
        None,
        "metadata_boundary".to_owned(),
        "audit".to_owned(),
        None,
        serde_json::json!({
            "code": "hidden-code",
            "state": "hidden-state",
            "nonce": "hidden-nonce",
            "session": "hidden-session",
            "csrf": "hidden-csrf",
            "otp": "hidden-otp",
            "jwt": "hidden-jwt",
            "cookie": "hidden-cookie",
            "signature": "hidden-signature",
            "password": "hidden-password",
            "token": "hidden-token",
            "secret": "hidden-secret",
            "credential": "hidden-credential",
            "private_key": "hidden-private-key",
            "api_key": "hidden-api-key",
            "authorization_code": "hidden-authorization-code",
            "code_challenge": "hidden-code-challenge",
            "code_verifier": "hidden-code-verifier",
            "not_a_token": "retained",
            "password_configured": false,
            "token_count": 4,
            "token_type": "Bearer",
            "token_type_hint": "access_token",
            "authorization_code_ttl_seconds": 60,
            "external_login_state_ttl_seconds": 600
        }),
    );

    for key in [
        "code",
        "state",
        "nonce",
        "session",
        "csrf",
        "otp",
        "jwt",
        "cookie",
        "signature",
        "password",
        "token",
        "secret",
        "credential",
        "private_key",
        "api_key",
        "authorization_code",
        "code_challenge",
        "code_verifier",
    ] {
        assert!(event.metadata.get(key).is_none(), "{key} must be redacted");
    }
    assert_eq!(event.metadata["not_a_token"], "retained");
    assert_eq!(event.metadata["password_configured"], false);
    assert_eq!(event.metadata["token_count"], 4);
    assert_eq!(event.metadata["token_type"], "Bearer");
    assert_eq!(event.metadata["token_type_hint"], "access_token");
    assert_eq!(event.metadata["authorization_code_ttl_seconds"], 60);
    assert_eq!(event.metadata["external_login_state_ttl_seconds"], 600);
}

#[test]
fn audit_event_replaces_embedded_credential_assignments_as_a_whole() {
    let event = AuditEvent::new(
        "system".to_owned(),
        None,
        "callback".to_owned(),
        "oauth".to_owned(),
        None,
        serde_json::json!({
            "redirect": "https://client.example/callback?code=hidden-code&state=hidden-state",
            "details": "nonce=hidden-nonce token=hidden-token",
            "safe": "result=success",
            "token_type": "Bearer",
            "configured": "password_configured=true"
        }),
    );

    assert_eq!(event.metadata["redirect"], "[REDACTED]");
    assert_eq!(event.metadata["details"], "[REDACTED]");
    assert_eq!(event.metadata["safe"], "result=success");
    assert_eq!(event.metadata["token_type"], "Bearer");
    assert_eq!(event.metadata["configured"], "password_configured=true");

    let serialized = serde_json::to_string(&event.metadata).expect("metadata serializes");
    for secret in [
        "hidden-code",
        "hidden-state",
        "hidden-nonce",
        "hidden-token",
    ] {
        assert!(!serialized.contains(secret));
    }
}

#[test]
fn security_failure_event_has_a_stable_failure_contract() {
    let event = AuditEvent::security_failure(
        "login_failure".to_owned(),
        "anonymous".to_owned(),
        None,
        "external_oauth".to_owned(),
        Some("example".to_owned()),
        "provider_unavailable",
    );

    assert_eq!(event.action, "login_failure");
    assert_eq!(event.metadata["result"], "failure");
    assert_eq!(event.metadata["reason"], "provider_unavailable");
}

#[test]
fn authentication_failure_keeps_stable_account_reference_and_canonical_ip() {
    let event = AuditEvent::authentication_failure(
        "login_failure".to_owned(),
        "anonymous".to_owned(),
        None,
        "authentication".to_owned(),
        None,
        "invalid_credentials",
        Some("  Alice@Example.COM "),
        Some("2001:0db8:0:0:0:0:0:1"),
        None,
    );

    assert_eq!(
        event.metadata["account_ref"],
        stable_account_reference("alice@example.com")
    );
    assert_eq!(event.metadata["source_ip"], "2001:db8::1");
    let serialized = serde_json::to_string(&event.metadata).expect("metadata serializes");
    assert!(!serialized.contains("Alice@Example.COM"));
    assert!(!serialized.contains("password"));
}

#[test]
fn invalid_actor_id_is_rejected_instead_of_becoming_null() {
    let event = AuditEvent::new(
        "user".to_owned(),
        Some("not-a-database-id".to_owned()),
        "login".to_owned(),
        "session".to_owned(),
        None,
        serde_json::json!({}),
    );

    assert!(matches!(event.validate(), Err(AuditError::InvalidActorId)));
}

#[tokio::test]
async fn audit_write_failure_is_returned_to_the_caller() {
    let pool = chenxing_auth::sqlx::postgres::PgPoolOptions::new()
        .acquire_timeout(Duration::from_millis(100))
        .connect_lazy("postgres://127.0.0.1:1/unused")
        .expect("lazy pool");
    let service = AuditService::new(pool);
    let event = AuditEvent::new(
        "system".to_owned(),
        None,
        "login".to_owned(),
        "session".to_owned(),
        None,
        serde_json::json!({}),
    );

    assert!(matches!(
        service.record(event).await,
        Err(AuditError::Database(_))
    ));
}

#[test]
fn authorization_denial_event_captures_actor_and_permission() {
    // Issue #73: 授权失败审计事件必须记录 actor、尝试访问的权限和失败原因
    let event = AuditEvent::security_failure(
        "admin_authorization_denied".to_owned(),
        "user".to_owned(),
        Some("42".to_owned()),
        "admin_permission".to_owned(),
        Some("ManageUsers".to_owned()),
        "insufficient_role",
    );

    assert_eq!(event.action, "admin_authorization_denied");
    assert_eq!(event.actor_type, "user");
    assert_eq!(event.actor_id, Some("42".to_owned()));
    assert_eq!(event.resource_type, "admin_permission");
    assert_eq!(event.resource_id, Some("ManageUsers".to_owned()));
    assert_eq!(event.metadata["result"], "failure");
    assert_eq!(event.metadata["reason"], "insufficient_role");
}

#[test]
fn authorization_denial_uses_best_effort_pattern() {
    // Issue #73: authorization.rs 授权拒绝路径使用 best-effort 审计——
    // 与 handlers.rs 的阻断式凭据签发策略不同
    const AUTHORIZATION_RS: &str = include_str!("../src/admin/authorization.rs");

    assert!(
        AUTHORIZATION_RS.contains("record_authz_denial"),
        "authorization.rs 必须通过 record_authz_denial 记录授权失败"
    );
    assert!(
        AUTHORIZATION_RS.contains("admin_authorization_denied"),
        "审计事件 action 必须为 admin_authorization_denied"
    );
    assert!(
        AUTHORIZATION_RS.contains("audit.authorization_denial_unrecorded"),
        "best-effort 路径必须在写入失败时记录 tracing::error"
    );
    assert!(
        AUTHORIZATION_RS.contains("best-effort"),
        "模块注释必须说明 best-effort 策略及其选择依据"
    );
}
