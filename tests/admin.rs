use chenxing_auth::admin::AdminAuthenticator;

#[test]
fn admin_authenticator_accepts_only_configured_token() {
    let authenticator = AdminAuthenticator::new("admin-secret".to_owned());

    assert!(authenticator.is_valid("admin-secret"));
    assert!(!authenticator.is_valid("wrong-secret"));
}

#[test]
fn admin_authenticator_rejects_empty_configuration() {
    let authenticator = AdminAuthenticator::new(String::new());

    assert!(!authenticator.is_valid(""));
    assert!(!authenticator.is_valid("anything"));
}
