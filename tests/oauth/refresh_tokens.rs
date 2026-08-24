use chenxing_auth::oauth::refresh::{RefreshToken, RefreshTokenError};
use time::OffsetDateTime;

#[test]
fn refresh_token_is_bound_to_client_and_user() {
    let token = RefreshToken::new(
        "cx_project".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );

    assert!(token.is_valid_for("cx_project", OffsetDateTime::now_utc()));
    assert!(!token.is_valid_for("another_client", OffsetDateTime::now_utc()));
}

#[test]
fn expired_refresh_token_is_rejected() {
    let mut token = RefreshToken::new(
        "cx_project".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );
    token.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);

    assert_eq!(
        token.validate("cx_project", OffsetDateTime::now_utc()),
        Err(RefreshTokenError::Expired)
    );
}

#[test]
fn refresh_token_does_not_store_oidc_nonce() {
    let token = RefreshToken::new(
        "cx_project".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
    );

    let value = serde_json::to_value(token).expect("refresh token serializes");
    assert!(value.get("nonce").is_none());
}
