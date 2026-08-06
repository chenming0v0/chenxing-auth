use chenxing_auth::oauth::code::{AuthorizationCode, CodeError};
use chenxing_auth::sessions::domain::session_token_hash;
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
        None,
    );

    assert_eq!(code.nonce.as_deref(), Some("nonce-value"));
}

/// 授权码必须携带签发时的会话绑定（AGENTS.md：授权码绑定 Client、
/// Redirect URI 和用户会话）；`AuthorizationCode::new` 是无会话的降级构造。
#[test]
fn authorization_code_binds_the_issuing_session() {
    let bound = AuthorizationCode::new_with_nonce(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
        None,
        Some("session-token".to_owned()),
    );
    let expected_hash = session_token_hash("session-token");
    assert_eq!(
        bound.session_token_hash.as_deref(),
        Some(expected_hash.as_str())
    );

    let unbound = AuthorizationCode::new(
        "cx_project".to_owned(),
        "https://project.example/callback".to_owned(),
        "user-1".to_owned(),
        vec!["openid".to_owned()],
        "challenge".to_owned(),
    );
    assert!(unbound.session_token_hash.is_none());
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
