use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, rand_core::RngCore},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::key_storage::{
    KeyStorageLock, TemporaryFileKind, atomic_write_in, cleanup_stale_temporary_files_in,
    ensure_secure_directory, read_secure_file,
};

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
    #[error(
        "provider secret key is missing while encrypted provider or SMTP credentials exist; restore oauth-provider-secret.key before startup"
    )]
    MissingKeyForPersistedSecrets,
    #[error("secret encryption failed")]
    Encryption,
    #[error("secret encoding failed")]
    Encoding,
}

impl SecretManager {
    /// Load the provider/SMTP encryption key, generating it only for a true bootstrap.
    ///
    /// `persisted_ciphertext_exists` must be derived from PostgreSQL before this blocking
    /// file operation starts. Regenerating after ciphertext has been persisted would make
    /// every existing credential permanently unreadable, so a missing file then fails closed.
    pub fn load_or_generate(
        directory: impl AsRef<Path>,
        persisted_ciphertext_exists: bool,
    ) -> Result<Self, SecretError> {
        let directory = directory.as_ref().to_path_buf();
        ensure_secure_directory(&directory)?;
        // 与 KeyManager 共享目录，但不共用临时文件前缀。持锁后再清理本命名空间的
        // 半成品，这样既不会删掉 KeyManager 正在写的 `.chenxing-key-*.tmp`，也不会
        // 在另一个 SecretManager 写入中途把 `.chenxing-secret-*.tmp` 清掉。
        let _lock = KeyStorageLock::acquire(&directory)?;
        cleanup_stale_temporary_files_in(&directory, TemporaryFileKind::ProviderSecret)?;
        let path = directory.join(SECRET_KEY_FILE);
        let key = match read_secure_file(&path) {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if persisted_ciphertext_exists {
                    return Err(SecretError::MissingKeyForPersistedSecrets);
                }
                let mut generated = vec![0_u8; KEY_LENGTH];
                rand::rngs::OsRng.fill_bytes(&mut generated);
                match atomic_write_in(TemporaryFileKind::ProviderSecret, &path, &generated, false) {
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
    use super::{SecretError, SecretManager};
    use std::fs;

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

    #[test]
    fn load_cleans_only_provider_secret_temporary_files() {
        let directory = std::env::temp_dir().join(format!(
            "chenxing-secret-ns-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let _manager = SecretManager::load_or_generate(&directory, false).expect("provider secret");
        let key_temporary = directory.join(".chenxing-key-in-flight.tmp");
        let secret_temporary = directory.join(".chenxing-secret-crashed.tmp");
        fs::write(&key_temporary, b"signing-key temp").expect("key temp");
        fs::write(&secret_temporary, b"provider-secret temp").expect("secret temp");

        let _reloaded = SecretManager::load_or_generate(&directory, false).expect("reload");

        assert!(
            key_temporary.exists(),
            "signing key temps must survive secret manager cleanup"
        );
        assert!(
            !secret_temporary.exists(),
            "secret namespace temps must be cleaned by secret manager"
        );

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn concurrent_first_init_converges_on_one_provider_secret() {
        let directory = std::env::temp_dir().join(format!(
            "chenxing-secret-race-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let directory = directory.clone();
                std::thread::spawn(move || SecretManager::load_or_generate(directory, false))
            })
            .collect();
        let managers: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker").expect("init"))
            .collect();
        let probe = managers[0].encrypt("same-key").expect("encrypt");
        for manager in &managers {
            assert_eq!(manager.decrypt(&probe).expect("decrypt"), "same-key");
        }

        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn first_initialization_without_ciphertext_generates_provider_secret() {
        let directory = std::env::temp_dir().join(format!(
            "chenxing-secret-bootstrap-{}",
            uuid::Uuid::new_v4().simple()
        ));

        let manager =
            SecretManager::load_or_generate(&directory, false).expect("bootstrap provider secret");

        assert!(manager.path().is_some_and(|path| path.is_file()));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn missing_provider_secret_requires_restoring_the_original_key() {
        let directory = std::env::temp_dir().join(format!(
            "chenxing-secret-recovery-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let manager =
            SecretManager::load_or_generate(&directory, false).expect("initial provider secret");
        let ciphertext = manager.encrypt("recoverable-secret").expect("encrypt");
        let key_path = manager.path().expect("persisted key path").to_path_buf();
        let original_key = fs::read(&key_path).expect("read original key for recovery fixture");
        drop(manager);
        fs::remove_file(&key_path).expect("simulate missing provider secret key");

        let error = SecretManager::load_or_generate(&directory, true)
            .err()
            .expect("persisted ciphertext must prevent key regeneration");
        assert!(matches!(error, SecretError::MissingKeyForPersistedSecrets));
        assert!(
            !key_path.exists(),
            "failure must not write a replacement key"
        );

        fs::write(&key_path, original_key).expect("restore original provider secret key");
        let recovered =
            SecretManager::load_or_generate(&directory, true).expect("load restored key");
        assert_eq!(
            recovered
                .decrypt(&ciphertext)
                .expect("decrypt after recovery"),
            "recoverable-secret"
        );

        let _ = fs::remove_dir_all(directory);
    }
}
