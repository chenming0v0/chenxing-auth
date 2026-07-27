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
