use chenxing_auth::oauth::pkce::{PkceError, verify_s256};

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
