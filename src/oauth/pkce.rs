use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PkceError {
    #[error("PKCE verifier must be 43 to 128 characters")]
    InvalidVerifier,
    #[error("PKCE verifier does not match challenge")]
    Mismatch,
}

pub fn verify_s256(verifier: &str, challenge: &str) -> Result<(), PkceError> {
    if !(43..=128).contains(&verifier.len()) {
        return Err(PkceError::InvalidVerifier);
    }
    let digest = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    if encoded != challenge {
        return Err(PkceError::Mismatch);
    }
    Ok(())
}
