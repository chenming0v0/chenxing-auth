use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::AuthEncryptionKeyRing;

const MAGIC: &[u8; 2] = b"EC";
const VERSION: u8 = 1;
const NONCE_LENGTH: usize = 12;
const MAX_KID_LENGTH: usize = 64;
const AAD_PREFIX: &str = "chenxing-email-change-code-v1";

#[derive(Debug, Error)]
pub(crate) enum EmailCodeCryptoError {
    #[error("email code encryption failed")]
    Encryption,
    #[error("email code ciphertext is malformed")]
    Malformed,
    #[error("email code key is unavailable")]
    UnknownKeyId,
    #[error("email code authentication failed")]
    Authentication,
}

pub(crate) fn encrypt_code(
    keys: &AuthEncryptionKeyRing,
    code: &str,
    user_id: i64,
    challenge_id: Uuid,
) -> Result<Zeroizing<Vec<u8>>, EmailCodeCryptoError> {
    let kid = keys.active_kid();
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH || !kid.is_ascii() {
        return Err(EmailCodeCryptoError::Malformed);
    }
    let cipher = Aes256Gcm::new_from_slice(keys.active_key().as_bytes())
        .map_err(|_| EmailCodeCryptoError::Encryption)?;
    let mut nonce_bytes = [0_u8; NONCE_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: code.as_bytes(),
                aad: &aad(user_id, challenge_id),
            },
        )
        .map_err(|_| EmailCodeCryptoError::Encryption)?;

    let mut encrypted = Vec::with_capacity(4 + kid.len() + NONCE_LENGTH + ciphertext.len());
    encrypted.extend_from_slice(MAGIC);
    encrypted.push(VERSION);
    encrypted.push(kid.len() as u8);
    encrypted.extend_from_slice(kid.as_bytes());
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend(ciphertext);
    Ok(Zeroizing::new(encrypted))
}

pub(crate) fn decrypt_code(
    keys: &AuthEncryptionKeyRing,
    encrypted: &[u8],
    user_id: i64,
    challenge_id: Uuid,
) -> Result<Zeroizing<Vec<u8>>, EmailCodeCryptoError> {
    let (kid, nonce_start) = parse_header(encrypted)?;
    let nonce_end = nonce_start
        .checked_add(NONCE_LENGTH)
        .ok_or(EmailCodeCryptoError::Malformed)?;
    let nonce = encrypted
        .get(nonce_start..nonce_end)
        .ok_or(EmailCodeCryptoError::Malformed)?;
    let ciphertext = encrypted
        .get(nonce_end..)
        .filter(|value| !value.is_empty())
        .ok_or(EmailCodeCryptoError::Malformed)?;
    let key = keys.key(&kid).ok_or(EmailCodeCryptoError::UnknownKeyId)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|_| EmailCodeCryptoError::Authentication)?;
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad(user_id, challenge_id),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| EmailCodeCryptoError::Authentication)
}

fn aad(user_id: i64, challenge_id: Uuid) -> Vec<u8> {
    format!("{AAD_PREFIX}:{user_id}:{challenge_id}").into_bytes()
}

fn parse_header(encrypted: &[u8]) -> Result<(String, usize), EmailCodeCryptoError> {
    if encrypted.len() < MAGIC.len() + 2
        || !encrypted.starts_with(MAGIC)
        || encrypted[MAGIC.len()] != VERSION
    {
        return Err(EmailCodeCryptoError::Malformed);
    }
    let kid_length = encrypted[MAGIC.len() + 1] as usize;
    if kid_length == 0 || kid_length > MAX_KID_LENGTH {
        return Err(EmailCodeCryptoError::Malformed);
    }
    let kid_start = MAGIC.len() + 2;
    let nonce_start = kid_start
        .checked_add(kid_length)
        .ok_or(EmailCodeCryptoError::Malformed)?;
    let minimum_length = nonce_start
        .checked_add(NONCE_LENGTH)
        .and_then(|length| length.checked_add(16))
        .ok_or(EmailCodeCryptoError::Malformed)?;
    if encrypted.len() < minimum_length {
        return Err(EmailCodeCryptoError::Malformed);
    }
    let kid = std::str::from_utf8(
        encrypted
            .get(kid_start..nonce_start)
            .ok_or(EmailCodeCryptoError::Malformed)?,
    )
    .map_err(|_| EmailCodeCryptoError::Malformed)?
    .to_owned();
    if !kid.is_ascii() {
        return Err(EmailCodeCryptoError::Malformed);
    }
    Ok((kid, nonce_start))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthEncryptionKey, AuthEncryptionKeyRing};

    fn keys(active: &str) -> AuthEncryptionKeyRing {
        AuthEncryptionKeyRing::from_entries(
            active.to_owned(),
            vec![
                ("old".to_owned(), AuthEncryptionKey::new([1; 32])),
                ("new".to_owned(), AuthEncryptionKey::new([2; 32])),
            ],
        )
        .expect("email code keys")
    }

    #[test]
    fn encrypted_code_round_trips_without_plaintext() {
        let ring = keys("new");
        let challenge_id = Uuid::new_v4();
        let encrypted = encrypt_code(&ring, "123456", 7, challenge_id).expect("encrypt");
        assert_ne!(encrypted.as_slice(), b"123456");
        assert_eq!(
            decrypt_code(&ring, encrypted.as_slice(), 7, challenge_id)
                .expect("decrypt")
                .as_slice(),
            b"123456"
        );
    }

    #[test]
    fn previous_key_remains_readable_during_rotation() {
        let challenge_id = Uuid::new_v4();
        let encrypted = encrypt_code(&keys("old"), "654321", 7, challenge_id).expect("encrypt");
        assert_eq!(
            decrypt_code(&keys("new"), encrypted.as_slice(), 7, challenge_id)
                .expect("decrypt")
                .as_slice(),
            b"654321"
        );
    }

    #[test]
    fn malformed_or_unknown_ciphertext_fails_closed() {
        let ring = keys("new");
        assert!(matches!(
            decrypt_code(&ring, b"invalid", 7, Uuid::new_v4()),
            Err(EmailCodeCryptoError::Malformed)
        ));
        let encrypted = encrypt_code(&keys("old"), "123456", 7, Uuid::new_v4()).expect("encrypt");
        assert!(matches!(
            decrypt_code(&ring, encrypted.as_slice(), 7, Uuid::new_v4()),
            Err(EmailCodeCryptoError::UnknownKeyId)
        ));
    }
}
