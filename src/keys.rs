//! JWK/JWKS key storage, publication, rotation, and revocation boundary.
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use pkcs8::PrivateKeyInfo;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use zeroize::Zeroizing;

use crate::clock::{Clock, SystemClock};
use crate::key_storage::{
    atomic_write, ensure_secure_directory, modified_time, secure_existing_file,
};
const ACTIVE_KEY_ID_FILE: &str = "active-rs256.kid";
const KEY_FILE_PREFIX: &str = "rs256-";
const KEY_FILE_SUFFIX: &str = ".pkcs1.der";
pub const DEFAULT_KEY_RETENTION_SECONDS: u64 = 604_800;
#[derive(Clone)]
pub struct KeyManager {
    state: Arc<RwLock<KeyState>>,
    rotation_lock: Arc<Mutex<()>>,
}
struct KeyState {
    directory: Option<PathBuf>,
    retention: Duration,
    active_key_id: String,
    active_encoding_key: EncodingKey,
    private_materials: BTreeMap<String, KeyMaterial>,
    verification_keys: BTreeMap<String, DecodingKey>,
    jwks: JwkSet,
}

/// RSA 私钥的 PKCS#1 DER 字节。
///
/// Rust 的 drop 只归还内存、不保证擦除内容：`Vec<u8>` 丢弃后私钥字节仍留在堆上，直到被分配器
/// 复用覆盖，期间 coredump、swap 落盘或同进程内存扫描都可能还原出完整私钥。`Zeroizing` 在
/// drop 时原地清零以消除该窗口，所有流经内存的私钥字节都必须用它包装。
type PrivateKeyDer = Zeroizing<Vec<u8>>;
#[derive(Clone)]
struct KeyMaterial {
    /// `Zeroizing` 的 clone 仍带清零语义，轮换时克隆的旧材料副本也会被擦除。
    der: PrivateKeyDer,
    created_at: OffsetDateTime,
}
/// 手写 `Debug`：派生实现会整段打印私钥 DER，一旦 `KeyMaterial` 被记进日志或断言失败信息，
/// 就等于泄漏签名私钥。（`Zeroizing` 本身也未实现 `Debug`，无法派生。）
impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeyMaterial")
            .field("der", &"<redacted>")
            .field("created_at", &self.created_at)
            .finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRotation {
    pub key_id: String,
    pub published_key_count: usize,
}
#[derive(Debug, Error)]
pub enum KeyManagerError {
    #[error("failed to generate RSA key")]
    Generation,
    #[error("failed to encode RSA key")]
    Encoding,
    #[error("failed to parse generated RSA key")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("failed to create JWT key: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("key storage operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("persisted key id is invalid")]
    InvalidKeyId,
    #[error("key rotation worker failed")]
    RotationWorker,
}
impl KeyManager {
    pub fn generate() -> Result<Self, KeyManagerError> {
        let (key_id, der) = generate_rsa_key()?;
        Self::from_key_material(None, key_id.clone(), [(key_id, der)], SystemClock.now())
    }
    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, KeyManagerError> {
        Self::load_or_generate_with_retention(
            directory,
            Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
        )
    }
    pub fn load_or_generate_with_retention(
        directory: impl AsRef<Path>,
        retention: Duration,
    ) -> Result<Self, KeyManagerError> {
        let now = SystemClock.now();
        let directory = directory.as_ref().to_path_buf();
        ensure_secure_directory(&directory)?;
        let active_id_path = directory.join(ACTIVE_KEY_ID_FILE);
        let active_id = read_optional_key_id(&active_id_path)?;
        cleanup_expired_key_files(&directory, active_id.as_deref(), retention, now)?;
        let mut key_files = discover_key_files(&directory)?;

        if key_files.is_empty() {
            migrate_legacy_key(&directory, &active_id_path, &mut key_files, now)?;
        } else {
            remove_legacy_key(&directory)?;
        }
        if key_files.is_empty() {
            let (key_id, der) = generate_rsa_key()?;
            persist_key(&directory, &key_id, &der)?;
            let created_at = OffsetDateTime::from(modified_time(
                &directory.join(key_file_name(&key_id)),
            )?);
            atomic_write(&active_id_path, key_id.as_bytes(), true)?;
            key_files.insert(key_id, key_material(der, created_at));
        }

        let active_key_id = match read_optional_key_id(&active_id_path)? {
            Some(key_id) if key_files.contains_key(&key_id) => key_id,
            _ => {
                let key_id = newest_key_id(&key_files).ok_or(KeyManagerError::InvalidKeyId)?;
                atomic_write(&active_id_path, key_id.as_bytes(), true)?;
                key_id
            }
        };
        prune_materials(
            Some(&directory),
            &active_key_id,
            &mut key_files,
            retention,
            now,
        );
        if !key_files.contains_key(&active_key_id) {
            return Err(KeyManagerError::InvalidKeyId);
        }
        Self::from_materials(Some(directory), retention, active_key_id, key_files)
    }
    pub async fn rotate(&self) -> Result<KeyRotation, KeyManagerError> {
        self.rotate_at(SystemClock.now()).await
    }

    pub async fn rotate_at(&self, now: OffsetDateTime) -> Result<KeyRotation, KeyManagerError> {
        let manager = self.clone();
        tokio::task::spawn_blocking(move || manager.rotate_blocking_at(now))
            .await
            .map_err(|_| KeyManagerError::RotationWorker)?
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
    fn rotate_blocking_at(&self, now: OffsetDateTime) -> Result<KeyRotation, KeyManagerError> {
        let _rotation_guard = self
            .rotation_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (directory, retention, mut materials) = {
            let state = self.read_state();
            (
                state.directory.clone(),
                state.retention,
                state.private_materials.clone(),
            )
        };
        let (key_id, der) = generate_rsa_key()?;
        prune_materials(directory.as_ref(), &key_id, &mut materials, retention, now);
        materials.insert(key_id.clone(), key_material(der.clone(), now));
        let next_state = build_key_state(directory.clone(), retention, key_id.clone(), materials)?;

        if let Some(directory) = directory.as_ref()
            && let Err(error) = persist_key(directory, &key_id, &der)
                .and_then(|_| persist_active_key_id(directory, &key_id))
        {
            let _ = fs::remove_file(directory.join(key_file_name(&key_id)));
            return Err(error);
        }

        let published_key_count = next_state.jwks.keys.len();
        {
            let mut state = self.write_state();
            *state = next_state;
        }

        if let Some(directory) = directory.as_ref()
            && let Err(error) = cleanup_expired_key_files(directory, Some(&key_id), retention, now)
        {
            tracing::warn!(error = %error, "failed to collect expired signing keys");
        }
        Ok(KeyRotation {
            key_id,
            published_key_count,
        })
    }

    fn from_key_material(
        directory: Option<PathBuf>,
        active_key_id: String,
        materials: impl IntoIterator<Item = (String, PrivateKeyDer)>,
        now: OffsetDateTime,
    ) -> Result<Self, KeyManagerError> {
        let materials = materials
            .into_iter()
            .map(|(key_id, der)| (key_id, key_material(der, now)))
            .collect();
        Self::from_materials(
            directory,
            Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
            active_key_id,
            materials,
        )
    }

    fn from_materials(
        directory: Option<PathBuf>,
        retention: Duration,
        active_key_id: String,
        materials: BTreeMap<String, KeyMaterial>,
    ) -> Result<Self, KeyManagerError> {
        Ok(Self {
            state: Arc::new(RwLock::new(build_key_state(
                directory,
                retention,
                active_key_id,
                materials,
            )?)),
            rotation_lock: Arc::new(Mutex::new(())),
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
    retention: Duration,
    active_key_id: String,
    private_materials: BTreeMap<String, KeyMaterial>,
) -> Result<KeyState, KeyManagerError> {
    validate_key_id(&active_key_id)?;
    let active_der = private_materials
        .get(&active_key_id)
        .map(|material| material.der.as_slice())
        .ok_or(KeyManagerError::InvalidKeyId)?;
    let mut verification_keys = BTreeMap::new();
    let mut jwks = Vec::new();

    for (key_id, material) in &private_materials {
        validate_key_id(key_id)?;
        let encoding_key = EncodingKey::from_rsa_der(&material.der);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)?;
        jwk.common.key_id = Some(key_id.clone());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        verification_keys.insert(key_id.clone(), DecodingKey::from_jwk(&jwk)?);
        jwks.push(jwk);
    }

    Ok(KeyState {
        directory,
        retention,
        active_key_id,
        active_encoding_key: EncodingKey::from_rsa_der(active_der),
        private_materials,
        verification_keys,
        jwks: JwkSet { keys: jwks },
    })
}

fn generate_rsa_key() -> Result<(String, PrivateKeyDer), KeyManagerError> {
    let key_pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| KeyManagerError::Generation)?;
    let pkcs8 = key_pair.as_der().map_err(|_| KeyManagerError::Encoding)?;
    let private_key_info = PrivateKeyInfo::try_from(pkcs8.as_ref())?;
    let der = Zeroizing::new(private_key_info.private_key.to_vec());
    Ok((format!("cx-{}", uuid::Uuid::new_v4().simple()), der))
}

fn discover_key_files(directory: &Path) -> Result<BTreeMap<String, KeyMaterial>, KeyManagerError> {
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
        let created_at = OffsetDateTime::from(modified_time(&path)?);
        // 从磁盘读入的私钥字节一进内存就包装成清零类型，避免中途留下裸 Vec 副本。
        let der = Zeroizing::new(fs::read(path)?);
        keys.insert(key_id, key_material(der, created_at));
    }
    Ok(keys)
}
fn cleanup_expired_key_files(
    directory: &Path,
    active_key_id: Option<&str>,
    retention: Duration,
    now: OffsetDateTime,
) -> Result<(), KeyManagerError> {
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
            .ok_or(KeyManagerError::InvalidKeyId)?;
        validate_key_id(key_id)?;
        let created_at = OffsetDateTime::from(modified_time(&path)?);
        if active_key_id != Some(key_id)
            && !within_retention_at(created_at, retention, now)
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}
fn migrate_legacy_key(
    directory: &Path,
    active_id_path: &Path,
    key_files: &mut BTreeMap<String, KeyMaterial>,
    now: OffsetDateTime,
) -> Result<(), KeyManagerError> {
    let legacy_path = directory.join("active-rs256.pkcs1.der");
    let metadata = match fs::symlink_metadata(&legacy_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        )
        .into());
    }
    secure_existing_file(&legacy_path)?;
    let key_id = match read_optional_key_id(active_id_path)? {
        Some(value) => value,
        None => format!("cx-{}", uuid::Uuid::new_v4().simple()),
    };
    validate_key_id(&key_id)?;
    let der = Zeroizing::new(fs::read(&legacy_path)?);
    persist_key(directory, &key_id, &der)?;
    persist_active_key_id(directory, &key_id)?;
    fs::remove_file(&legacy_path)?;
    key_files.insert(key_id, key_material(der, now));
    Ok(())
}
fn remove_legacy_key(directory: &Path) -> Result<(), KeyManagerError> {
    let legacy_path = directory.join("active-rs256.pkcs1.der");
    match fs::symlink_metadata(&legacy_path) {
        Ok(metadata) if metadata.is_file() => {
            secure_existing_file(&legacy_path)?;
            fs::remove_file(legacy_path)?;
        }
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "invalid secure storage path",
            )
            .into());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
fn persist_key(directory: &Path, key_id: &str, der: &[u8]) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    atomic_write(&directory.join(key_file_name(key_id)), der, false)?;
    Ok(())
}

fn persist_active_key_id(directory: &Path, key_id: &str) -> Result<(), KeyManagerError> {
    validate_key_id(key_id)?;
    atomic_write(&directory.join(ACTIVE_KEY_ID_FILE), key_id.as_bytes(), true)?;
    Ok(())
}
fn read_optional_key_id(path: &Path) -> Result<Option<String>, KeyManagerError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() {
        return Err(KeyManagerError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "invalid secure storage path",
        )));
    }
    secure_existing_file(path)?;
    let key_id = fs::read_to_string(path)?.trim().to_owned();
    validate_key_id(&key_id)?;
    Ok(Some(key_id))
}
fn newest_key_id(key_files: &BTreeMap<String, KeyMaterial>) -> Option<String> {
    key_files
        .iter()
        .max_by_key(|(_, material)| material.created_at)
        .map(|(key_id, _)| key_id.clone())
}

fn key_material(der: PrivateKeyDer, created_at: OffsetDateTime) -> KeyMaterial {
    KeyMaterial { der, created_at }
}

fn prune_materials(
    directory: Option<&PathBuf>,
    active_key_id: &str,
    materials: &mut BTreeMap<String, KeyMaterial>,
    retention: Duration,
    now: OffsetDateTime,
) {
    if directory.is_none() {
        return;
    }
    materials.retain(|key_id, material| {
        key_id == active_key_id || within_retention_at(material.created_at, retention, now)
    });
}

fn within_retention_at(
    created_at: OffsetDateTime,
    retention: Duration,
    now: OffsetDateTime,
) -> bool {
    let Ok(retention) = TimeDuration::try_from(retention) else {
        return false;
    };
    now >= created_at && now - created_at <= retention
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

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
