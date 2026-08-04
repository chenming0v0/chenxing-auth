use std::time::Duration;

use chenxing_auth::audit::{AuditError, AuditEvent, AuditService};

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
            "token_count": 3
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
    assert!(event.metadata.get("token_count").is_none());
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
