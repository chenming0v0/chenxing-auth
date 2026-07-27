//! JWK/JWKS key storage, publication, rotation, and revocation boundary.

use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, rand_core::OsRng};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};
use thiserror::Error;

const ACTIVE_KEY_ID_FILE: &str = "active-rs256.kid";
const KEY_FILE_PREFIX: &str = "rs256-";
const KEY_FILE_SUFFIX: &str = ".pkcs1.der";

#[derive(Clone)]
pub struct KeyManager {
    state: Arc<RwLock<KeyState>>,
}

struct KeyState {
    directory: Option<PathBuf>,
    active_key_id: String,
    active_encoding_key: EncodingKey,
    private_materials: BTreeMap<String, Vec<u8>>,
    verification_keys: BTreeMap<String, DecodingKey>,
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
        let (key_id, der) = generate_rsa_key()?;
        Self::from_key_material(None, key_id.clone(), [(key_id, der)])
    }

    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, KeyManagerError> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory)?;
        let active_id_path = directory.join(ACTIVE_KEY_ID_FILE);
        let mut key_files = discover_key_files(&directory)?;
        if key_files.is_empty() {
            migrate_legacy_key(&directory, &active_id_path, &mut key_files)?;
            if key_files.is_empty() {
                let (key_id, der) = generate_rsa_key()?;
                persist_key(&directory, &key_id, &der)?;
                key_files.insert(key_id.clone(), der);
                fs::write(&active_id_path, &key_id)?;
            }
        } else if !active_id_path.exists() {
            let key_id = key_files
                .keys()
                .next_back()
                .cloned()
                .ok_or(KeyManagerError::InvalidKeyId)?;
            fs::write(&active_id_path, key_id)?;
        }

        let active_key_id = read_key_id(&active_id_path)?;
        if !key_files.contains_key(&active_key_id) {
            return Err(KeyManagerError::InvalidKeyId);
        }
        Self::from_key_material(Some(directory), active_key_id, key_files)
    }

    pub fn rotate(&self) -> Result<(), KeyManagerError> {
        let (key_id, der) = generate_rsa_key()?;
        let mut state = self.write_state();
        let mut materials = state.private_materials.clone();
        if let Some(directory) = state.directory.as_ref() {
            persist_key(directory, &key_id, &der)?;
            fs::write(directory.join(ACTIVE_KEY_ID_FILE), &key_id)?;
        }
        materials.insert(key_id.clone(), der);
        *state = build_key_state(state.directory.clone(), key_id, materials)?;
        Ok(())
    }

    pub fn key_id(&self) -> String {
        self.read_state().active_key_id.clone()
    }

    pub fn encoding_key(&self) -> EncodingKey {
        self.read_state().active_encoding_key.clone()
    }

    pub fn decoding_key(&self) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        let key_id = self.key_id();
        self.decoding_key_for(&key_id)
    }

    pub fn decoding_key_for(
        &self,
        key_id: &str,
    ) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        self.read_state()
            .verification_keys
            .get(key_id)
            .cloned()
            .ok_or_else(|| {
                jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
            })
    }

    pub fn jwks(&self) -> JwkSet {
        self.read_state().jwks.clone()
    }

    fn from_key_material(
        directory: Option<PathBuf>,
        active_key_id: String,
        materials: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<Self, KeyManagerError> {
        Ok(Self {
            state: Arc::new(RwLock::new(build_key_state(
                directory,
                active_key_id,
                materials.into_iter().collect(),
            )?)),
        })
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, KeyState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, KeyState> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn build_key_state(
    directory: Option<PathBuf>,
    active_key_id: String,
    private_materials: BTreeMap<String, Vec<u8>>,
) -> Result<KeyState, KeyManagerError> {
    validate_key_id(&active_key_id)?;
    let active_der = private_materials
        .get(&active_key_id)
        .ok_or(KeyManagerError::InvalidKeyId)?;
    let mut verification_keys = BTreeMap::new();
    let mut jwks = Vec::new();

    for (key_id, der) in &private_materials {
        validate_key_id(key_id)?;
        let encoding_key = EncodingKey::from_rsa_der(der);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)?;
        jwk.common.key_id = Some(key_id.clone());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        verification_keys.insert(key_id.clone(), DecodingKey::from_jwk(&jwk)?);
        jwks.push(jwk);
    }

    Ok(KeyState {
        directory,
        active_key_id,
        active_encoding_key: EncodingKey::from_rsa_der(active_der),
        private_materials,
        verification_keys,
        jwks: JwkSet { keys: jwks },
    })
}

fn generate_rsa_key() -> Result<(String, Vec<u8>), KeyManagerError> {
    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let der = private_key.to_pkcs1_der()?.as_bytes().to_vec();
    Ok((format!("cx-{}", uuid::Uuid::new_v4().simple()), der))
}

fn discover_key_files(directory: &Path) -> Result<BTreeMap<String, Vec<u8>>, KeyManagerError> {
    let mut keys = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(KEY_FILE_PREFIX) || !file_name.ends_with(KEY_FILE_SUFFIX) {
            continue;
        }
        let key_id = file_name
            .strip_prefix(KEY_FILE_PREFIX)
            .and_then(|value| value.strip_suffix(KEY_FILE_SUFFIX))
            .ok_or(KeyManagerError::InvalidKeyId)?
            .to_owned();
        validate_key_id(&key_id)?;
        keys.insert(key_id, fs::read(path)?);
    }
    Ok(keys)
}

fn migrate_legacy_key(
    directory: &Path,
    active_id_path: &Path,
    key_files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), KeyManagerError> {
    let legacy_path = directory.join("active-rs256.pkcs1.der");
    if !legacy_path.exists() {
        return Ok(());
    }
    let key_id = match fs::read_to_string(active_id_path) {
        Ok(value) => value.trim().to_owned(),
        Err(_) => format!("cx-{}", uuid::Uuid::new_v4().simple()),
    };
    validate_key_id(&key_id)?;
    let der = fs::read(legacy_path)?;
    persist_key(directory, &key_id, &der)?;
    fs::write(active_id_path, &key_id)?;
    key_files.insert(key_id, der);
    Ok(())
}

fn persist_key(directory: &Path, key_id: &str, der: &[u8]) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    fs::write(directory.join(key_file_name(key_id)), der)?;
    Ok(())
}

fn read_key_id(path: &Path) -> Result<String, KeyManagerError> {
    let key_id = fs::read_to_string(path)?.trim().to_owned();
    validate_key_id(&key_id)?;
    Ok(key_id)
}

fn key_file_name(key_id: &str) -> String {
    format!("{KEY_FILE_PREFIX}{key_id}{KEY_FILE_SUFFIX}")
}

fn validate_key_id(key_id: &str) -> Result<(), KeyManagerError> {
    if key_id.is_empty()
        || !key_id.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
    {
        return Err(KeyManagerError::InvalidKeyId);
    }
    Ok(())
}
