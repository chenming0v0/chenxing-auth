use chenxing_auth::oauth::code::{AuthorizationCode, CodeError};
use time::OffsetDateTime;

#[test]
fn authorization_code_can_be_redeemed_only_once() {
    let mut code = AuthorizationCode::new(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );

    assert!(code.redeem_at(OffsetDateTime::now_utc()).is_ok());
    assert_eq!(
        code.redeem_at(OffsetDateTime::now_utc()),
        Err(CodeError::AlreadyRedeemed)
    );
}

#[test]
fn authorization_code_preserves_oidc_nonce() {
    let code = AuthorizationCode::new_with_nonce(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        Some("nonce-value".to_owned()),
    );

    assert_eq!(code.nonce.as_deref(), Some("nonce-value"));
}

#[test]
fn expired_authorization_code_cannot_be_redeemed() {
    let mut code = AuthorizationCode::new(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );

    code.expires_at = OffsetDateTime::now_utc() - time::Duration::seconds(1);

    assert_eq!(
        code.redeem_at(OffsetDateTime::now_utc()),
        Err(CodeError::Expired)
    );
}
