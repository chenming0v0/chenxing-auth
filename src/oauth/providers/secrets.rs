use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::key_storage::{atomic_write, ensure_secure_directory, read_secure_file};

const SECRET_KEY_FILE: &str = "oauth-provider-secret.key";
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;

#[derive(Clone)]
pub struct SecretManager {
    key: [u8; KEY_LENGTH],
    path: Option<PathBuf>,
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("secret key storage failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret key has invalid length")]
    InvalidKeyLength,
    #[error("secret encryption failed")]
    Encryption,
    #[error("secret encoding failed")]
    Encoding,
}

impl SecretManager {
    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, SecretError> {
        let directory = directory.as_ref().to_path_buf();
        ensure_secure_directory(&directory)?;
        let path = directory.join(SECRET_KEY_FILE);
        let key = match read_secure_file(&path) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut generated = vec![0_u8; KEY_LENGTH];
                rand::rngs::OsRng.fill_bytes(&mut generated);
                match atomic_write(&path, &generated, false) {
                    Ok(()) => generated,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        read_secure_file(&path)?
                    }
                    Err(error) => return Err(SecretError::Io(error)),
                }
            }
            Err(error) => return Err(error.into()),
        };
        let key: [u8; KEY_LENGTH] = key.try_into().map_err(|_| SecretError::InvalidKeyLength)?;
        Ok(Self {
            key,
            path: Some(path),
        })
    }

    pub fn from_key(key: [u8; KEY_LENGTH]) -> Self {
        Self { key, path: None }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, SecretError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| SecretError::Encryption)?;
        let mut nonce_bytes = [0_u8; NONCE_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
            .map_err(|_| SecretError::Encryption)?;
        let mut encoded = nonce_bytes.to_vec();
        encoded.extend(ciphertext);
        Ok(encoded)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<String, SecretError> {
        if ciphertext.len() <= NONCE_LENGTH {
            return Err(SecretError::Encoding);
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| SecretError::Encryption)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&ciphertext[..NONCE_LENGTH]),
                &ciphertext[NONCE_LENGTH..],
            )
            .map_err(|_| SecretError::Encoding)?;
        String::from_utf8(plaintext).map_err(|_| SecretError::Encoding)
    }

    pub fn encode(ciphertext: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(ciphertext)
    }

    pub fn decode(value: &str) -> Result<Vec<u8>, SecretError> {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| SecretError::Encoding)
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::SecretManager;

    #[test]
    fn encrypted_secret_can_be_decrypted_but_does_not_contain_plaintext() {
        let manager = SecretManager::from_key([7_u8; 32]);
        let ciphertext = manager.encrypt("top-secret").expect("encrypt");

        assert!(
            !ciphertext
                .windows("top-secret".len())
                .any(|window| window == b"top-secret")
        );
        assert_eq!(manager.decrypt(&ciphertext).expect("decrypt"), "top-secret");
        assert!(manager.decrypt(b"invalid").is_err());
    }
}
