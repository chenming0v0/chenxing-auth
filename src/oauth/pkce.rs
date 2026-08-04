use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
    if !(43..=128).contains(&challenge.len()) {
        return Err(PkceError::InvalidChallenge);
    }
    if !challenge
        .bytes()
        .all(|character| character.is_ascii_alphanumeric() || b"-._~".contains(&character))
    {
        return Err(PkceError::InvalidChallengeCharacters);
    }
    if challenge.len() != 43 {
        return Err(PkceError::InvalidChallenge);
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
