use chenxing_auth::audit::AuditEvent;

#[test]
fn audit_event_redacts_sensitive_values_from_metadata() {
    let event = AuditEvent::new(
        "user".to_owned(),
        Some("user-1".to_owned()),
        "login".to_owned(),
        "session".to_owned(),
        Some("session-1".to_owned()),
        serde_json::json!({"password": "do-not-store", "result": "success"}),
    );

    assert!(event.metadata.get("password").is_none());
    assert_eq!(event.metadata["result"], "success");
}
