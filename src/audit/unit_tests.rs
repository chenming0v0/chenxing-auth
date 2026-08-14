use super::*;

#[test]
fn audit_event_serializes_creation_time_as_rfc3339() {
    let mut event = AuditEvent::new_raw(
        "system".to_owned(),
        None,
        "test".to_owned(),
        "test".to_owned(),
        None,
        serde_json::json!({}),
    );
    event.created_at = OffsetDateTime::UNIX_EPOCH;

    let value = serde_json::to_value(event).expect("audit event serializes");
    assert_eq!(value["created_at"], "1970-01-01T00:00:00Z");
}

#[test]
fn retries_only_known_safe_database_failures() {
    assert!(is_retryable_database_error(&AuditError::Database(
        crate::sqlx::Error::PoolTimedOut,
    )));
    assert!(!is_retryable_database_error(&AuditError::Database(
        crate::sqlx::Error::Protocol("connection outcome is unknown".to_owned()),
    )));
    assert!(!is_retryable_database_error(&AuditError::InvalidActorType));
}
