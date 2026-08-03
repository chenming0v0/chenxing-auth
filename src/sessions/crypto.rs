use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;

use super::store::SessionStoreError;
use crate::config::AuthEncryptionKeyRing;

const PAYLOAD_MAGIC: &[u8; 4] = b"CHX1";
const PAYLOAD_NONCE_LENGTH: usize = 12;
const MAX_KID_LENGTH: usize = u16::MAX as usize;

pub(crate) fn encrypt(
    keys: &AuthEncryptionKeyRing,
    payload: &[u8],
) -> Result<Vec<u8>, SessionStoreError> {
    let kid = keys.active_kid().as_bytes();
    if kid.is_empty() || kid.len() > MAX_KID_LENGTH {
        return Err(SessionStoreError::PayloadEncryption);
    }
    let cipher = Aes256Gcm::new_from_slice(keys.active_key().as_bytes())
        .map_err(|_| SessionStoreError::PayloadEncryption)?;
    let mut nonce_bytes = [0_u8; PAYLOAD_NONCE_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), payload)
        .map_err(|_| SessionStoreError::PayloadEncryption)?;

    let mut encrypted = Vec::with_capacity(
        PAYLOAD_MAGIC.len() + 2 + kid.len() + PAYLOAD_NONCE_LENGTH + ciphertext.len(),
    );
    encrypted.extend_from_slice(PAYLOAD_MAGIC);
    encrypted.extend_from_slice(&(kid.len() as u16).to_be_bytes());
    encrypted.extend_from_slice(kid);
    encrypted.extend_from_slice(&nonce_bytes);
    encrypted.extend(ciphertext);
    Ok(encrypted)
}

pub(crate) fn decrypt(
    keys: &AuthEncryptionKeyRing,
    encrypted: &[u8],
) -> Result<Vec<u8>, SessionStoreError> {
    if encrypted.len() <= PAYLOAD_NONCE_LENGTH {
        return Err(SessionStoreError::PayloadDecryption);
    }
    if encrypted.starts_with(PAYLOAD_MAGIC) {
        return decrypt_keyed(keys, encrypted);
    }

    // Payloads written before the key-ring format had no kid. Keep them
    // readable while the configured migration window still contains a key.
    keys.iter()
        .find_map(|(_, key)| decrypt_with_key(key.as_bytes(), encrypted))
        .ok_or(SessionStoreError::PayloadDecryption)
}

fn decrypt_keyed(
    keys: &AuthEncryptionKeyRing,
    encrypted: &[u8],
) -> Result<Vec<u8>, SessionStoreError> {
    let kid_length = u16::from_be_bytes(
        encrypted
            .get(4..6)
            .ok_or(SessionStoreError::PayloadDecryption)?
            .try_into()
            .map_err(|_| SessionStoreError::PayloadDecryption)?,
    ) as usize;
    let nonce_start = 6usize
        .checked_add(kid_length)
        .ok_or(SessionStoreError::PayloadDecryption)?;
    let nonce_end = nonce_start
        .checked_add(PAYLOAD_NONCE_LENGTH)
        .ok_or(SessionStoreError::PayloadDecryption)?;
    let kid = std::str::from_utf8(
        encrypted
            .get(6..nonce_start)
            .ok_or(SessionStoreError::PayloadDecryption)?,
    )
    .map_err(|_| SessionStoreError::PayloadDecryption)?;
    let nonce = encrypted
        .get(nonce_start..nonce_end)
        .ok_or(SessionStoreError::PayloadDecryption)?;
    let ciphertext = encrypted
        .get(nonce_end..)
        .filter(|value| !value.is_empty())
        .ok_or(SessionStoreError::PayloadDecryption)?;
    let plaintext = if let Some(key) = keys.key(kid) {
        decrypt_with_parts(key.as_bytes(), nonce, ciphertext).ok()
    } else {
        // The compatibility constructor labels its key "legacy". During rotation,
        // that same key can be retained under a different configured kid.
        keys.iter()
            .find_map(|(_, key)| decrypt_with_parts(key.as_bytes(), nonce, ciphertext).ok())
    };
    plaintext.ok_or(SessionStoreError::PayloadDecryption)
}

fn decrypt_with_key(key: &[u8; 32], encrypted: &[u8]) -> Option<Vec<u8>> {
    let (nonce, ciphertext) = encrypted.split_at(PAYLOAD_NONCE_LENGTH);
    decrypt_with_parts(key, nonce, ciphertext).ok()
}

fn decrypt_with_parts(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SessionStoreError> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| SessionStoreError::PayloadDecryption)?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| SessionStoreError::PayloadDecryption)
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt};
    use crate::config::{AuthEncryptionKey, AuthEncryptionKeyRing};

    fn rotated_ring(active: &str) -> AuthEncryptionKeyRing {
        AuthEncryptionKeyRing::from_entries(
            active.to_owned(),
            vec![
                ("current".to_owned(), AuthEncryptionKey::new([1; 32])),
                ("previous".to_owned(), AuthEncryptionKey::new([2; 32])),
            ],
        )
        .expect("test key ring")
    }

    #[test]
    fn payload_written_with_new_key_is_readable_by_the_rotation_ring() {
        let current = rotated_ring("current");
        let encrypted = encrypt(&current, b"session payload").expect("encrypt");
        assert_eq!(
            decrypt(&current, &encrypted).expect("decrypt"),
            b"session payload"
        );
    }

    #[test]
    fn payload_written_with_previous_key_remains_readable_during_migration() {
        let previous = rotated_ring("previous");
        let encrypted = encrypt(&previous, b"old session payload").expect("encrypt");
        let current = rotated_ring("current");
        assert_eq!(
            decrypt(&current, &encrypted).expect("decrypt old payload"),
            b"old session payload"
        );
    }

    #[test]
    fn payload_with_legacy_key_id_is_readable_using_previous_key() {
        let legacy = AuthEncryptionKeyRing::single(AuthEncryptionKey::new([2; 32]));
        let encrypted = encrypt(&legacy, b"legacy session payload").expect("encrypt");
        let current = rotated_ring("current");

        assert_eq!(
            decrypt(&current, &encrypted).expect("decrypt legacy payload"),
            b"legacy session payload"
        );
    }

    #[test]
    fn unknown_key_id_is_a_controlled_decryption_failure() {
        let current = rotated_ring("current");
        let previous = AuthEncryptionKeyRing::from_entries(
            "previous".to_owned(),
            vec![("previous".to_owned(), AuthEncryptionKey::new([2; 32]))],
        )
        .expect("test key ring");
        let encrypted = encrypt(&current, b"session payload").expect("encrypt");
        assert!(decrypt(&previous, &encrypted).is_err());
    }

    #[test]
    fn malformed_payload_is_a_controlled_decryption_failure() {
        let keys = rotated_ring("current");
        let mut malformed_keyed = b"CHX1".to_vec();
        malformed_keyed.extend_from_slice(&1_u16.to_be_bytes());
        malformed_keyed.push(b'x');
        malformed_keyed.extend_from_slice(&[0; 12]);

        for payload in [
            b"CHX1".to_vec(),
            malformed_keyed,
            [b"CHX1".as_slice(), &[0, 1, 0xff], &[0; 12], &[1]].concat(),
        ] {
            assert!(decrypt(&keys, &payload).is_err());
        }
    }
}
