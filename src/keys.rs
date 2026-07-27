//! JWK/JWKS key storage, publication, rotation, and revocation boundary.

use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, EncodingKey};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, rand_core::OsRng};
use std::{fs, path::Path};
use thiserror::Error;

#[derive(Clone)]
pub struct KeyManager {
    key_id: String,
    encoding_key: EncodingKey,
    jwks: JwkSet,
}

#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("failed to generate RSA key: {0}")]
    Generation(#[from] rsa::errors::Error),
    #[error("failed to encode RSA key: {0}")]
    Encoding(#[from] rsa::pkcs1::Error),
    #[error("failed to create JWT key: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("key storage operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("persisted key id is invalid")]
    InvalidKeyId,
}

impl KeyManager {
    pub fn generate() -> Result<Self, KeyManagerError> {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let der = private_key.to_pkcs1_der()?;
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        let key_id = format!("cx-{}", uuid::Uuid::new_v4().simple());
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)?;
        jwk.common.key_id = Some(key_id.clone());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);

        Ok(Self {
            key_id,
            encoding_key,
            jwks: JwkSet { keys: vec![jwk] },
        })
    }

    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, KeyManagerError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let path = directory.join("active-rs256.pkcs1.der");
        let key_id_path = directory.join("active-rs256.kid");
        if path.exists() {
            let der = fs::read(path)?;
            let key_id = match fs::read_to_string(&key_id_path) {
                Ok(value) if !value.trim().is_empty() => value.trim().to_owned(),
                _ => {
                    let value = format!("cx-{}", uuid::Uuid::new_v4().simple());
                    fs::write(&key_id_path, &value)?;
                    value
                }
            };
            return Self::from_der(&der, key_id);
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let der = private_key.to_pkcs1_der()?.as_bytes().to_vec();
        let key_id = format!("cx-{}", uuid::Uuid::new_v4().simple());
        fs::write(path, &der)?;
        fs::write(key_id_path, &key_id)?;
        Self::from_der(&der, key_id)
    }

    fn from_der(der: &[u8], key_id: String) -> Result<Self, KeyManagerError> {
        let encoding_key = EncodingKey::from_rsa_der(der);
        Self::from_encoding_key(key_id, encoding_key)
    }

    fn from_encoding_key(
        key_id: String,
        encoding_key: EncodingKey,
    ) -> Result<Self, KeyManagerError> {
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)?;
        jwk.common.key_id = Some(key_id.clone());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);

        Ok(Self {
            key_id,
            encoding_key,
            jwks: JwkSet { keys: vec![jwk] },
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }

    pub fn decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error> {
        jsonwebtoken::DecodingKey::from_jwk(&self.jwks.keys[0])
    }

    pub fn jwks(&self) -> JwkSet {
        self.jwks.clone()
    }
}
