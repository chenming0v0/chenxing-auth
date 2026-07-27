use chenxing_auth::sessions::domain::Session;
use std::time::Duration;

#[test]
fn session_has_a_csrf_token_for_browser_state_changes() {
    let session =
        Session::new("user-1".to_owned(), Duration::from_secs(60)).expect("valid session");

    assert!(session.csrf_token.len() >= 32);
    assert!(session.validates_csrf(&session.csrf_token));
    assert!(!session.validates_csrf("wrong-csrf-token"));
}
