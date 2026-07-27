use chenxing_auth::keys::KeyManager;
use chenxing_auth::oauth::{id_token::issue_id_token, token::issue_access_token};

#[test]
fn access_token_is_signed_with_current_key_and_contains_scope() {
    let keys = KeyManager::generate().expect("signing key");
    let token = issue_access_token(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        &["openid".to_owned(), "profile".to_owned()],
        3600,
    )
    .expect("access token");

    let header = jsonwebtoken::decode_header(&token).expect("JWT header");
    assert_eq!(header.kid.as_deref(), Some(keys.key_id()));
    assert_eq!(header.alg, jsonwebtoken::Algorithm::RS256);
}

#[test]
fn id_token_contains_oidc_subject_audience_and_nonce() {
    let keys = KeyManager::generate().expect("signing key");
    let token = issue_id_token(
        &keys,
        "https://auth.example.com",
        "user-1",
        "cx_project",
        Some("nonce-value"),
        3600,
    )
    .expect("ID token");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(&["https://auth.example.com"]);
    validation.set_audience(&["cx_project"]);
    let claims = jsonwebtoken::decode::<chenxing_auth::oauth::id_token::IdTokenClaims>(
        &token,
        &keys.decoding_key().expect("decoding key"),
        &validation,
    )
    .expect("valid ID token")
    .claims;

    assert_eq!(claims.sub, "user-1");
    assert_eq!(claims.aud, "cx_project");
    assert_eq!(claims.nonce.as_deref(), Some("nonce-value"));
}
