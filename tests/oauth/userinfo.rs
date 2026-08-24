use chenxing_auth::oauth::userinfo::UserInfoClaims;

#[test]
fn userinfo_claims_expose_only_requested_optional_claims() {
    let claims = UserInfoClaims::from_profile(
        "user-1".to_owned(),
        "user@example.com".to_owned(),
        Some("辰星用户".to_owned()),
        &["openid".to_owned(), "email".to_owned()],
    );

    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.email.as_deref(), Some("user@example.com"));
    assert_eq!(claims.name, None);
}
