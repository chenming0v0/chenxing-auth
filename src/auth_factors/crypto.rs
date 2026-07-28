use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rand::{RngCore, rngs::OsRng};
use thiserror::Error;

const NONCE_LENGTH: usize = 12;

#[derive(Debug, Error)]
pub enum SecretCryptoError {
    #[error("authentication key is invalid")]
    InvalidKey,
    #[error("encrypted secret is malformed")]
    Malformed,
    #[error("encrypted secret authentication failed")]
    Authentication,
}

pub fn encrypt_totp_secret(key: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SecretCryptoError::InvalidKey)?;
    let less_safe = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut encrypted = secret.to_vec();
    less_safe
        .seal_in_place_append_tag(nonce, Aad::empty(), &mut encrypted)
        .map_err(|_| SecretCryptoError::Authentication)?;
    let mut output = Vec::with_capacity(NONCE_LENGTH + encrypted.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn decrypt_totp_secret(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
    if encrypted.len() < NONCE_LENGTH + aead::AES_256_GCM.tag_len() {
        return Err(SecretCryptoError::Malformed);
    }
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SecretCryptoError::InvalidKey)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; NONCE_LENGTH] = encrypted[..NONCE_LENGTH]
        .try_into()
        .map_err(|_| SecretCryptoError::Malformed)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut payload = encrypted[NONCE_LENGTH..].to_vec();
    let plaintext = less_safe
        .open_in_place(nonce, Aad::empty(), &mut payload)
        .map_err(|_| SecretCryptoError::Authentication)?;
    Ok(plaintext.to_vec())
}
