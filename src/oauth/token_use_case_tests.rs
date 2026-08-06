use super::*;
use crate::oauth::code::AuthorizationCode;
use time::Duration;

const CLIENT_ID: &str = "cx_client";
const REDIRECT_URI: &str = "https://client.example/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

fn authorization_code() -> AuthorizationCode {
    AuthorizationCode::new(
        CLIENT_ID.to_owned(),
        REDIRECT_URI.to_owned(),
        "7".to_owned(),
        vec!["openid".to_owned()],
        CHALLENGE.to_owned(),
    )
}

#[test]
fn binding_and_pkce_validation_accepts_a_valid_code_without_consuming_it() {
    let code = authorization_code();

    assert!(validate_code_binding(CLIENT_ID, REDIRECT_URI, VERIFIER, &code).is_ok());
    assert!(code.redeemed_at.is_none());
}

#[test]
fn redirect_binding_is_rejected_as_invalid_grant() {
    let code = authorization_code();

    let error = validate_code_binding(
        CLIENT_ID,
        "https://attacker.example/callback",
        VERIFIER,
        &code,
    )
    .expect_err("redirect URI mismatch must reject the code");

    assert_eq!(error, OAuthError::invalid_grant());
}

#[test]
fn expired_code_is_rejected_before_pkce_and_remains_unconsumed() {
    let mut code = authorization_code();
    code.expires_at = time::OffsetDateTime::now_utc() - Duration::seconds(1);

    let error = validate_code_binding(
        CLIENT_ID,
        REDIRECT_URI,
        "invalid-verifier-that-would-fail-pkce-too",
        &code,
    )
    .expect_err("expired code must reject");

    assert_eq!(error, OAuthError::invalid_grant());
    assert!(code.redeemed_at.is_none());
}

#[test]
fn pkce_mismatch_is_rejected_without_consuming_the_code() {
    let code = authorization_code();

    let error = validate_code_binding(
        CLIENT_ID,
        REDIRECT_URI,
        "a".repeat(43).as_str(),
        &code,
    )
    .expect_err("PKCE mismatch must reject");

    assert_eq!(error, OAuthError::invalid_grant());
    assert!(code.redeemed_at.is_none());
}
