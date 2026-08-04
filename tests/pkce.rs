use chenxing_auth::oauth::pkce::{PkceError, validate_s256_challenge, verify_s256};

#[test]
fn pkce_s256_accepts_matching_verifier() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    assert!(verify_s256(verifier, challenge).is_ok());
}

#[test]
fn pkce_s256_rejects_wrong_verifier() {
    let error = verify_s256(
        "wrong-verifier-that-is-long-enough-for-pkce-validation-1234567890",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    )
    .expect_err("wrong verifier must be rejected");

    assert_eq!(error, PkceError::Mismatch);
}

#[test]
fn pkce_s256_rejects_invalid_verifier_length() {
    let error = verify_s256("short", "challenge").expect_err("short verifier must be rejected");

    assert_eq!(error, PkceError::InvalidVerifier);
}

#[test]
fn pkce_s256_rejects_verifier_with_disallowed_characters() {
    let error = verify_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjk!", "challenge")
        .expect_err("PKCE verifier must use the RFC 7636 character set");

    assert_eq!(error, PkceError::InvalidCharacters);
}

#[test]
fn pkce_s256_challenge_accepts_standard_base64url_digest() {
    assert!(validate_s256_challenge("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM").is_ok());
}

#[test]
fn pkce_s256_challenge_rejects_invalid_length_and_characters() {
    let challenges = vec![
        "x".to_owned(),
        "a".repeat(129),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw cM".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-中".to_owned(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw!cM".to_owned(),
    ];
    for challenge in challenges {
        assert!(
            validate_s256_challenge(&challenge).is_err(),
            "{challenge:?}"
        );
    }
}
