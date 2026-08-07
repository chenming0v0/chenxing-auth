use chenxing_auth::sessions::domain::Session;
use std::time::Duration;

#[test]
fn session_is_active_until_expiry_and_revocation() {
    let mut session =
        Session::new("user-1".to_owned(), Duration::from_secs(60)).expect("valid session");

    assert!(session.is_active_at(session.created_at));
    assert!(!session.is_active_at(session.expires_at));

    session.revoke();
    assert!(!session.is_active_at(session.created_at));
}

#[test]
fn session_rejects_zero_ttl() {
    assert!(Session::new("user-1".to_owned(), Duration::ZERO).is_err());
}

#[test]
fn idle_timeout_invalidates_inactive_sessions_without_moving_absolute_expiry() {
    let created_at = time::OffsetDateTime::UNIX_EPOCH;
    let session = Session::new_at_with_idle_timeout(
        "user-1".to_owned(),
        Duration::from_secs(600),
        Duration::from_secs(30),
        created_at,
    )
    .expect("valid session");

    assert_eq!(session.expires_at, created_at + time::Duration::seconds(600));
    assert!(session.is_active_at(created_at + time::Duration::seconds(29)));
    assert!(!session.is_active_at(created_at + time::Duration::seconds(30)));
}

#[test]
fn idle_timeout_is_validated_when_a_policy_session_is_created() {
    assert!(Session::new_with_idle_timeout(
        "user-1".to_owned(),
        Duration::from_secs(60),
        Duration::ZERO,
    )
    .is_err());
}
