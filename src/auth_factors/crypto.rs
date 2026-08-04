use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rand::{RngCore, rngs::OsRng};
use thiserror::Error;

use crate::config::AuthEncryptionKeyRing;

const NONCE_LENGTH: usize = 12;
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_MAGIC: [u8; 2] = *b"CX";
const ENVELOPE_PREFIX_LENGTH: usize = ENVELOPE_MAGIC.len() + 2;
const MAX_KID_LENGTH: usize = 64;

#[derive(Debug, Error)]
pub enum SecretCryptoError {
    #[error("authentication key is invalid")]
    InvalidKey,
    #[error("encrypted secret is malformed")]
    Malformed,
    #[error("encrypted secret authentication failed")]
    Authentication,
    #[error("encrypted secret key is unavailable")]
    UnknownKeyId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedTotpSecret {
    pub plaintext: Vec<u8>,
    pub needs_reencryption: bool,
}

pub fn encrypt_totp_secret(key: &[u8; 32], secret: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
    let encrypted = encrypt_totp_secret_with_kid("legacy", key, secret)?;
    Ok(encrypted[ENVELOPE_PREFIX_LENGTH + "legacy".len()..].to_vec())
}

pub fn encrypt_totp_secret_with_ring(
    keys: &AuthEncryptionKeyRing,
    secret: &[u8],
) -> Result<Vec<u8>, SecretCryptoError> {
    encrypt_totp_secret_with_kid(keys.active_kid(), keys.active_key().as_bytes(), secret)
}

fn encrypt_totp_secret_with_kid(
    kid: &str,
    key: &[u8; 32],
    secret: &[u8],
) -> Result<Vec<u8>, SecretCryptoError> {
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH || !kid.is_ascii() {
        return Err(SecretCryptoError::Malformed);
    }
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
    let mut output = Vec::with_capacity(
        ENVELOPE_PREFIX_LENGTH + kid.len() + NONCE_LENGTH + encrypted.len(),
    );
    output.extend_from_slice(&ENVELOPE_MAGIC);
    output.push(ENVELOPE_VERSION);
    output.push(kid.len() as u8);
    output.extend_from_slice(kid.as_bytes());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

pub fn decrypt_totp_secret(key: &[u8; 32], encrypted: &[u8]) -> Result<Vec<u8>, SecretCryptoError> {
    let nonce_offset = if encrypted.starts_with(&ENVELOPE_MAGIC) {
        let (_, nonce_offset) = envelope_metadata(encrypted)?;
        nonce_offset
    } else {
        0
    };
    decrypt_payload(key, encrypted, nonce_offset)
}

pub fn decrypt_totp_secret_with_ring(
    keys: &AuthEncryptionKeyRing,
    encrypted: &[u8],
) -> Result<DecryptedTotpSecret, SecretCryptoError> {
    let (stored_kid, nonce_offset) = if encrypted.starts_with(&ENVELOPE_MAGIC) {
        let (kid, nonce_offset) = envelope_metadata(encrypted)?;
        (Some(kid), nonce_offset)
    } else if is_legacy_ciphertext(encrypted) {
        (None, 0)
    } else {
        return Err(SecretCryptoError::Malformed);
    };

    let mut candidates = Vec::new();
    if let Some(kid) = stored_kid.as_deref() {
        let Some(key) = keys.key(kid) else {
            return Err(SecretCryptoError::UnknownKeyId);
        };
        candidates.push(key);
    } else {
        candidates.extend(keys.iter().map(|(_, key)| key));
    }

    for key in candidates {
        match decrypt_payload(key.as_bytes(), encrypted, nonce_offset) {
            Ok(plaintext) => {
                let needs_reencryption = stored_kid
                    .as_deref()
                    .map(|kid| kid != keys.active_kid())
                    .unwrap_or(true);
                return Ok(DecryptedTotpSecret {
                    plaintext,
                    needs_reencryption,
                });
            }
            Err(SecretCryptoError::Authentication) => continue,
            Err(error) => return Err(error),
        }
    }

    Err(SecretCryptoError::Authentication)
}

fn decrypt_payload(
    key: &[u8; 32],
    encrypted: &[u8],
    nonce_offset: usize,
) -> Result<Vec<u8>, SecretCryptoError> {
    if encrypted.len() < nonce_offset + NONCE_LENGTH + aead::AES_256_GCM.tag_len() {
        return Err(SecretCryptoError::Malformed);
    }
    let unbound =
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SecretCryptoError::InvalidKey)?;
    let less_safe = LessSafeKey::new(unbound);
    let nonce_bytes: [u8; NONCE_LENGTH] = encrypted[nonce_offset..nonce_offset + NONCE_LENGTH]
        .try_into()
        .map_err(|_| SecretCryptoError::Malformed)?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut payload = encrypted[nonce_offset + NONCE_LENGTH..].to_vec();
    let plaintext = less_safe
        .open_in_place(nonce, Aad::empty(), &mut payload)
        .map_err(|_| SecretCryptoError::Authentication)?;
    Ok(plaintext.to_vec())
}

fn envelope_metadata(encrypted: &[u8]) -> Result<(String, usize), SecretCryptoError> {
    if encrypted.len() < ENVELOPE_PREFIX_LENGTH {
        return Err(SecretCryptoError::Malformed);
    }
    if !encrypted.starts_with(&ENVELOPE_MAGIC) || encrypted[2] != ENVELOPE_VERSION {
        return Err(SecretCryptoError::Malformed);
    }
    let kid_length = encrypted[3] as usize;
    if kid_length == 0 || kid_length > MAX_KID_LENGTH {
        return Err(SecretCryptoError::Malformed);
    }
    let kid_end = ENVELOPE_PREFIX_LENGTH + kid_length;
    if encrypted.len() < kid_end + NONCE_LENGTH + aead::AES_256_GCM.tag_len() {
        return Err(SecretCryptoError::Malformed);
    }
    let kid = std::str::from_utf8(&encrypted[ENVELOPE_PREFIX_LENGTH..kid_end])
        .map_err(|_| SecretCryptoError::Malformed)?
        .to_owned();
    Ok((kid, kid_end))
}

fn is_legacy_ciphertext(encrypted: &[u8]) -> bool {
    encrypted.len() >= NONCE_LENGTH + aead::AES_256_GCM.tag_len()
        && !encrypted.starts_with(&ENVELOPE_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuthEncryptionKey;

    fn rotated_ring(active_kid: &str) -> AuthEncryptionKeyRing {
        AuthEncryptionKeyRing::from_entries(
            active_kid.to_owned(),
            vec![
                ("old".to_owned(), AuthEncryptionKey::new([1; 32])),
                ("new".to_owned(), AuthEncryptionKey::new([2; 32])),
            ],
        )
        .expect("valid key ring")
    }

    #[test]
    fn encrypted_secret_records_kid_and_survives_key_rotation() {
        let old_ring = rotated_ring("old");
        let encrypted = encrypt_totp_secret_with_ring(&old_ring, b"totp-secret")
            .expect("encrypt secret");

        let rotated = rotated_ring("new");
        let decrypted = decrypt_totp_secret_with_ring(&rotated, &encrypted)
            .expect("decrypt with previous key");
        assert_eq!(decrypted.plaintext, b"totp-secret");
        assert!(decrypted.needs_reencryption);
    }

    #[test]
    fn legacy_secret_is_read_and_marked_for_reencryption() {
        let legacy = encrypt_totp_secret(&[1; 32], b"legacy-secret").expect("encrypt secret");
        let rotated = rotated_ring("new");
        let decrypted = decrypt_totp_secret_with_ring(&rotated, &legacy).expect("decrypt secret");

        assert_eq!(decrypted.plaintext, b"legacy-secret");
        assert!(decrypted.needs_reencryption);
    }

    #[test]
    fn unknown_kid_is_not_retried_with_another_key() {
        let encrypted = encrypt_totp_secret_with_ring(&rotated_ring("old"), b"secret")
            .expect("encrypt secret");
        let keys = AuthEncryptionKeyRing::single(AuthEncryptionKey::new([2; 32]));

        assert!(matches!(
            decrypt_totp_secret_with_ring(&keys, &encrypted),
            Err(SecretCryptoError::UnknownKeyId)
        ));
    }
}
