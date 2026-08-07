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
use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

#[path = "keys_persistence.rs"]
mod persistence;
#[path = "keys_revocation.rs"]
mod revocation;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRevocation {
    pub key_id: String,
    pub active_key_id: String,
    pub published_key_count: usize,
}

/// 签发一次令牌所需的不可撕裂密钥快照。
///
/// `key_id` 和 `encoding_key` 来自同一份 `KeyState` 读取，调用方不得分别从
/// `KeyManager` 读取它们，否则轮换恰好发生在两次读取之间时会产生错误的 JWT。
#[derive(Clone)]
pub struct ActiveSigningKey {
    key_id: String,
    encoding_key: EncodingKey,
}

impl ActiveSigningKey {
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }
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
    #[error("requested signing key is not published")]
    UnknownKeyId,
    #[error("signing key storage is busy")]
    StorageBusy,
    #[error("key rotation worker failed")]
    RotationWorker,
    #[error("key operation worker failed")]
    KeyWorker,
    #[error("cannot revoke the active signing key without another valid signing key")]
    NoActiveKeyReplacement,
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
        let _storage_lock = KeyStorageLock::acquire(&directory)?;
        let (active_key_id, key_files) =
            persistence::load_materials(&directory, retention, now, true)?;
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

    pub async fn revoke(&self, key_id: impl AsRef<str>) -> Result<KeyRevocation, KeyManagerError> {
        self.revoke_at(key_id.as_ref().to_owned(), SystemClock.now())
            .await
    }

    pub async fn revoke_at(
        &self,
        key_id: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<KeyRevocation, KeyManagerError> {
        let manager = self.clone();
        let key_id = key_id.into();
        tokio::task::spawn_blocking(move || revocation::revoke_blocking_at(&manager, key_id, now))
            .await
            .map_err(|_| KeyManagerError::KeyWorker)?
    }

    /// 返回当前进程内存中的兼容快照。协议签发必须使用 `active_signing_key`。
    pub fn key_id(&self) -> String {
        self.read_state().active_key_id.clone()
    }

    /// 返回当前进程内存中的兼容快照。协议签发必须使用 `active_signing_key`。
    pub fn encoding_key(&self) -> EncodingKey {
        self.read_state().active_encoding_key.clone()
    }

    pub fn active_signing_key(&self) -> Result<ActiveSigningKey, KeyManagerError> {
        self.refresh_from_disk()?;
        let state = self.read_state();
        Ok(ActiveSigningKey {
            key_id: state.active_key_id.clone(),
            encoding_key: state.active_encoding_key.clone(),
        })
    }

    /// 在使用验证材料前重新读取共享目录，避免实例永久保留旧的 active/JWKS 快照。
    pub fn refresh_from_disk(&self) -> Result<(), KeyManagerError> {
        let (directory, retention) = {
            let state = self.read_state();
            (state.directory.clone(), state.retention)
        };
        let Some(directory) = directory else {
            return Ok(());
        };
        ensure_secure_directory(&directory)?;
        let _storage_lock = KeyStorageLock::try_acquire(&directory).map_err(|error| {
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::AlreadyExists
            ) {
                KeyManagerError::StorageBusy
            } else {
                KeyManagerError::Io(error)
            }
        })?;
        let now = SystemClock.now();
        let (active_key_id, key_files) =
            persistence::load_materials(&directory, retention, now, false)?;
        let next_state = build_key_state(Some(directory), retention, active_key_id, key_files)?;
        *self.write_state() = next_state;
        Ok(())
    }

    pub fn verification_key_for(&self, key_id: &str) -> Result<DecodingKey, KeyManagerError> {
        self.refresh_from_disk()?;
        self.read_state()
            .verification_keys
            .get(key_id)
            .cloned()
            .ok_or(KeyManagerError::UnknownKeyId)
    }

    pub fn fresh_jwks(&self) -> Result<JwkSet, KeyManagerError> {
        self.refresh_from_disk()?;
        Ok(self.read_state().jwks.clone())
    }

    pub fn decoding_key(&self) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        self.refresh_from_disk()
            .map_err(|_| invalid_decoding_key_error())?;
        let state = self.read_state();
        state
            .verification_keys
            .get(&state.active_key_id)
            .cloned()
            .ok_or_else(invalid_decoding_key_error)
    }

    pub fn decoding_key_for(
        &self,
        key_id: &str,
    ) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        self.verification_key_for(key_id)
            .map_err(|_| invalid_decoding_key_error())
    }

    /// 返回当前进程内存中的兼容快照。JWKS HTTP 端点使用 `fresh_jwks`。
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
        if let Some(directory) = directory.as_ref() {
            ensure_secure_directory(directory)?;
        }
        let _storage_lock = match directory.as_ref() {
            Some(directory) => Some(KeyStorageLock::acquire(directory)?),
            None => None,
        };
        if let Some(directory) = directory.as_ref() {
            let (_, disk_materials) = persistence::load_materials(directory, retention, now, true)?;
            materials = disk_materials;
        }

        let (key_id, der) = generate_rsa_key()?;
        materials.insert(key_id.clone(), key_material(der.clone(), now));
        prune_materials(
            directory.as_deref(),
            &key_id,
            &mut materials,
            retention,
            now,
        );
        let next_state = build_key_state(directory.clone(), retention, key_id.clone(), materials)?;

        if let Some(directory) = directory.as_ref()
            && let Err(error) = persistence::persist_key(directory, &key_id, &der)
                .and_then(|_| persistence::persist_active_key_id(directory, &key_id))
        {
            let _ = fs::remove_file(directory.join(persistence::key_file_name(&key_id)));
            return Err(error);
        }

        let published_key_count = next_state.jwks.keys.len();
        {
            let mut state = self.write_state();
            *state = next_state;
        }

        if let Some(directory) = directory.as_ref()
            && let Err(error) =
                persistence::cleanup_expired_key_files(directory, Some(&key_id), retention, now)
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

fn invalid_decoding_key_error() -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
}

fn build_key_state(
    directory: Option<PathBuf>,
    retention: Duration,
    active_key_id: String,
    private_materials: BTreeMap<String, KeyMaterial>,
) -> Result<KeyState, KeyManagerError> {
    persistence::validate_key_id(&active_key_id)?;
    let active_der = private_materials
        .get(&active_key_id)
        .map(|material| material.der.as_slice())
        .ok_or(KeyManagerError::InvalidKeyId)?;
    let mut verification_keys = BTreeMap::new();
    let mut jwks = Vec::new();

    for (key_id, material) in &private_materials {
        persistence::validate_key_id(key_id)?;
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
    let pkcs8 = {
        let encoded = key_pair.as_der().map_err(|_| KeyManagerError::Encoding)?;
        // Keep an owned copy zeroizing too; the parsed PKCS#1 material is another sensitive copy.
        Zeroizing::new(encoded.as_ref().to_vec())
    };
    let der = {
        let private_key_info = PrivateKeyInfo::try_from(pkcs8.as_slice())?;
        Zeroizing::new(private_key_info.private_key.to_vec())
    };
    Ok((format!("cx-{}", uuid::Uuid::new_v4().simple()), der))
}

fn key_material(der: PrivateKeyDer, created_at: OffsetDateTime) -> KeyMaterial {
    KeyMaterial { der, created_at }
}

fn prune_materials(
    directory: Option<&Path>,
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
    // created_at 晚于 now 说明这个 key 是在该时间快照之后写入的：并发轮换各自在
    // 抢锁之前捕获 now，后执行的轮换可能持有更早的快照。晚于参照时刻创建的 key
    // 不可能已经超过自创建起算的保留期，必须保留。
    // 这也符合"轮换时保留必要的旧公钥验证窗口"：宁可多留一瞬，不可误删仍在 JWKS
    // 中公布的验证密钥。
    if now < created_at {
        return true;
    }
    now - created_at <= retention
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
