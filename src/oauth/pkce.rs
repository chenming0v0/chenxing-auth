use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// S256 challenge 固定长度：32 字节 SHA-256 摘要经 base64url 无填充编码后为 43 字符
/// RFC 7636 §4.2: code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
const S256_CHALLENGE_LENGTH: usize = 43;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PkceError {
    #[error("PKCE verifier must be 43 to 128 characters")]
    InvalidVerifier,
    #[error("PKCE verifier contains disallowed characters")]
    InvalidCharacters,
    #[error("PKCE S256 challenge must be a 43-character base64url value")]
    InvalidChallenge,
    #[error("PKCE S256 challenge contains disallowed characters")]
    InvalidChallengeCharacters,
    #[error("PKCE verifier does not match challenge")]
    Mismatch,
}

pub fn validate_s256_challenge(challenge: &str) -> Result<(), PkceError> {
    // S256 challenge 必须恰好 43 字符（32 字节 SHA-256 摘要的 base64url 无填充长度）
    if challenge.len() != S256_CHALLENGE_LENGTH {
        return Err(PkceError::InvalidChallenge);
    }
    if !challenge
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || b"-._~".contains(&character))
    {
        return Err(PkceError::InvalidChallengeCharacters);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(challenge)
        .map_err(|_| PkceError::InvalidChallenge)?;
    if decoded.len() != Sha256::output_size() {
        return Err(PkceError::InvalidChallenge);
    }
    Ok(())
}

pub fn verify_s256(verifier: &str, challenge: &str) -> Result<(), PkceError> {
    // RFC 7636 §4.1: code_verifier 长度为 43-128 字符（可变长）
    // 注意：与 challenge 固定 43 字符不同，verifier 允许范围
    if !(43..=128).contains(&verifier.len()) {
        return Err(PkceError::InvalidVerifier);
    }
    if !verifier
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || b"-._~".contains(&character))
    {
        return Err(PkceError::InvalidCharacters);
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    if encoded != challenge {
        return Err(PkceError::Mismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_s256_challenge_accepts_valid_43_char() {
        // RFC 7636 测试向量
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(challenge.len(), 43);
        assert!(validate_s256_challenge(challenge).is_ok());
    }

    #[test]
    fn validate_s256_challenge_rejects_42_chars() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c";
        assert_eq!(challenge.len(), 42);
        let error = validate_s256_challenge(challenge).expect_err("42 字符应被拒绝");
        assert_eq!(error, PkceError::InvalidChallenge);
    }

    #[test]
    fn validate_s256_challenge_rejects_44_chars() {
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cMX";
        assert_eq!(challenge.len(), 44);
        let error = validate_s256_challenge(challenge).expect_err("44 字符应被拒绝");
        assert_eq!(error, PkceError::InvalidChallenge);
    }

    #[test]
    fn validate_s256_challenge_rejects_128_chars() {
        let challenge = "a".repeat(128);
        let error = validate_s256_challenge(&challenge).expect_err("128 字符应被拒绝");
        assert_eq!(error, PkceError::InvalidChallenge);
    }

    #[test]
    fn validate_s256_challenge_rejects_empty() {
        let error = validate_s256_challenge("").expect_err("空串应被拒绝");
        assert_eq!(error, PkceError::InvalidChallenge);
    }

    #[test]
    fn validate_s256_challenge_rejects_invalid_base64url_chars() {
        // '+' 和 '/' 属于标准 base64，但不属于 base64url
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw+cM";
        assert_eq!(challenge.len(), 43);
        let error = validate_s256_challenge(challenge).expect_err("'+' 应被拒绝");
        assert_eq!(error, PkceError::InvalidChallengeCharacters);
    }

    #[test]
    fn validate_s256_challenge_rejects_padding() {
        // base64url 无填充，'=' 应被拒绝
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-c=";
        assert_eq!(challenge.len(), 43);
        let error = validate_s256_challenge(challenge).expect_err("'=' 应被拒绝");
        assert_eq!(error, PkceError::InvalidChallengeCharacters);
    }

    #[test]
    fn verify_s256_accepts_43_char_verifier() {
        // RFC 7636 测试向量
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(verifier.len(), 43);
        assert!(verify_s256(verifier, challenge).is_ok());
    }

    #[test]
    fn verify_s256_accepts_128_char_verifier() {
        let verifier = "a".repeat(128);
        let challenge = "aDbPE7rEAOkQUHHNavRwhN-srU5eMCyUv-0k4BOvtz4";
        assert_eq!(verifier.len(), 128);
        assert!(verify_s256(&verifier, challenge).is_ok());
    }

    #[test]
    fn verify_s256_rejects_42_char_verifier() {
        let verifier = "a".repeat(42);
        let error = verify_s256(&verifier, "challenge").expect_err("42 字符 verifier 应被拒绝");
        assert_eq!(error, PkceError::InvalidVerifier);
    }

    #[test]
    fn verify_s256_rejects_129_char_verifier() {
        let verifier = "a".repeat(129);
        let error = verify_s256(&verifier, "challenge").expect_err("129 字符 verifier 应被拒绝");
        assert_eq!(error, PkceError::InvalidVerifier);
    }

    #[test]
    fn verify_s256_rejects_verifier_with_invalid_chars() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk+";
        let error = verify_s256(verifier, "challenge").expect_err("'+' 应被拒绝");
        assert_eq!(error, PkceError::InvalidCharacters);
    }

    #[test]
    fn verify_s256_rejects_mismatch() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let error = verify_s256(verifier, wrong_challenge).expect_err("不匹配应被拒绝");
        assert_eq!(error, PkceError::Mismatch);
    }
}
