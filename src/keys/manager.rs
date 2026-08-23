use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::Duration,
};

use time::OffsetDateTime;

use crate::clock::{Clock, SystemClock};
use crate::key_storage::{KeyStorageLock, ensure_secure_directory};

use super::{
    ActiveSigningKey, DEFAULT_KEY_RETENTION_SECONDS, KeyManager, KeyManagerError, KeyRevocation,
    KeyRotation, KeyState, PendingPublishedKey, activation, build_key_state, generate_rsa_key,
    journal,
    material::{KeyMaterial, PrivateKeyDer, key_material},
    persistence, revocation, rotation,
};

impl KeyManager {
    pub fn generate() -> Result<Self, KeyManagerError> {
        Self::generate_with_activation_delay(Duration::ZERO)
    }

    /// 纯内存管理器。`activation_delay` 为 0 时 `rotate` 立即接管签发，保持既有测试语义。
    pub fn generate_with_activation_delay(
        activation_delay: Duration,
    ) -> Result<Self, KeyManagerError> {
        let (key_id, der) = generate_rsa_key()?;
        Self::from_key_material(
            None,
            key_id.clone(),
            [(key_id, der)],
            SystemClock.now(),
            activation_delay,
        )
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
        Self::load_or_generate_with_retention_and_skew_allowance(
            directory,
            retention,
            Duration::ZERO,
        )
    }

    pub fn load_or_generate_with_retention_and_skew_allowance(
        directory: impl AsRef<Path>,
        retention: Duration,
        skew_allowance: Duration,
    ) -> Result<Self, KeyManagerError> {
        Self::load_or_generate_with_lifecycle(directory, retention, skew_allowance, Duration::ZERO)
    }

    /// 带完整生命周期参数的加载：保留窗口、时钟偏差容忍、发布后激活等待。
    ///
    /// 已落盘的 `pending-activation.record` 里的 `activate_at` 已包含发布时配置的
    /// `activation_delay + skew_allowance`，并优先于加载实例的当前配置。因此第二
    /// 实例即使以 delay=0 加载，也不会提前签发仍在传播窗口内的新密钥。
    pub fn load_or_generate_with_lifecycle(
        directory: impl AsRef<Path>,
        retention: Duration,
        skew_allowance: Duration,
        activation_delay: Duration,
    ) -> Result<Self, KeyManagerError> {
        let now = SystemClock.now();
        let directory = directory.as_ref().to_path_buf();
        ensure_secure_directory(&directory)?;
        let _storage_lock = KeyStorageLock::acquire(&directory)?;
        let (active_key_id, key_files) =
            persistence::load_materials(&directory, retention, skew_allowance, now, true)?;
        let pending = activation::read(&directory)?;
        Self::from_materials(
            Some(directory),
            retention,
            skew_allowance,
            activation_delay,
            active_key_id,
            key_files,
            pending,
        )
    }

    pub async fn rotate(&self) -> Result<KeyRotation, KeyManagerError> {
        self.rotate_at(SystemClock.now()).await
    }

    pub async fn rotate_at(&self, now: OffsetDateTime) -> Result<KeyRotation, KeyManagerError> {
        let manager = self.clone();
        tokio::task::spawn_blocking(move || rotation::rotate_blocking_at(&manager, now))
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
    pub fn encoding_key(&self) -> jsonwebtoken::EncodingKey {
        self.read_state().active_encoding_key.clone()
    }

    /// 取一份不可撕裂的签名快照，只读内存，不做磁盘 IO，因此不会失败。
    ///
    /// `key_id` 与 `encoding_key` 在同一次读锁内取出，轮换发生在两次读取之间也不会
    /// 签出 `kid` 与私钥不匹配的 JWT。
    pub fn active_signing_key(&self) -> ActiveSigningKey {
        let state = self.read_state();
        ActiveSigningKey {
            key_id: state.active_key_id.clone(),
            encoding_key: state.active_encoding_key.clone(),
        }
    }

    /// Return a consistent signing snapshot only while background synchronization is healthy.
    /// The flag is checked before and after cloning the state so a synchronization failure
    /// published during the read fails closed before a new signature is produced.
    pub fn active_signing_key_if_ready(&self) -> Option<ActiveSigningKey> {
        if !self.signing_ready() {
            return None;
        }
        let signing_key = self.active_signing_key();
        self.signing_ready().then_some(signing_key)
    }

    /// Whether the latest shared-directory synchronization permits token signing.
    pub fn signing_ready(&self) -> bool {
        self.sync_healthy.load(Ordering::Acquire)
    }

    pub(crate) fn mark_sync_healthy(&self, healthy: bool) {
        self.sync_healthy.store(healthy, Ordering::Release);
    }

    pub(crate) fn observe_revocation_generation(&self, generation: u64) {
        self.revocation_generation
            .store(generation, Ordering::Release);
        self.mark_sync_healthy(true);
    }

    /// 按 `kid` 取验证公钥，只读内存快照。
    ///
    /// `None` 表示这个 `kid` 不在当前已发布的密钥集合里，调用方必须按“令牌无效”
    /// 处理，而不是当成服务端故障：热路径不再区分“密钥不存在”和“磁盘暂时读不到”，
    /// 前者是协议结果，后者由后台同步任务负责收敛。
    ///
    /// 未命中时提示后台任务尽快同步一次共享目录，让别的实例刚轮换出的 `kid`
    /// 在下一次同步后可验证。
    pub fn verification_key_for(&self, key_id: &str) -> Option<jsonwebtoken::DecodingKey> {
        if !self.signing_ready() {
            return None;
        }
        let key = self.read_state().verification_keys.get(key_id).cloned();
        if key.is_none() {
            self.hint_resync();
        }
        key
    }

    pub fn decoding_key(&self) -> Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error> {
        if !self.signing_ready() {
            return Err(invalid_decoding_key_error());
        }
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
    ) -> Result<jsonwebtoken::DecodingKey, jsonwebtoken::errors::Error> {
        self.verification_key_for(key_id)
            .ok_or_else(invalid_decoding_key_error)
    }

    /// 当前已发布的公钥集合，JWKS 端点直接返回这份内存快照。
    pub fn jwks(&self) -> jsonwebtoken::jwk::JwkSet {
        self.read_state().jwks.clone()
    }

    /// 请求后台同步任务尽快对齐一次磁盘快照。
    ///
    /// 单实例（无共享目录）下没有后台任务在等这个通道，提示被静默丢弃；
    /// `Notify::notify_one` 会保留一个许可，同步进行中到达的提示也不会丢。
    pub fn hint_resync(&self) {
        self.resync_hint.notify_one();
    }

    fn from_key_material(
        directory: Option<PathBuf>,
        active_key_id: String,
        materials: impl IntoIterator<Item = (String, PrivateKeyDer)>,
        now: OffsetDateTime,
        activation_delay: Duration,
    ) -> Result<Self, KeyManagerError> {
        let materials = materials
            .into_iter()
            .map(|(key_id, der)| (key_id, key_material(der, now)))
            .collect();
        Self::from_materials(
            directory,
            Duration::from_secs(DEFAULT_KEY_RETENTION_SECONDS),
            // 纯内存模式没有第二个实例，不存在跨实例时钟偏差。
            Duration::ZERO,
            activation_delay,
            active_key_id,
            materials,
            None,
        )
    }

    fn from_materials(
        directory: Option<PathBuf>,
        retention: Duration,
        skew_allowance: Duration,
        activation_delay: Duration,
        active_key_id: String,
        materials: BTreeMap<String, KeyMaterial>,
        pending: Option<PendingPublishedKey>,
    ) -> Result<Self, KeyManagerError> {
        let persisted_generation = directory
            .as_ref()
            .map(|directory| journal::revocation_generation(directory))
            .transpose()?
            .unwrap_or(0);
        Ok(Self {
            state: std::sync::Arc::new(std::sync::RwLock::new(build_key_state(
                directory,
                retention,
                skew_allowance,
                activation_delay,
                active_key_id,
                materials,
                pending,
            )?)),
            rotation_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
            resync_hint: std::sync::Arc::new(tokio::sync::Notify::new()),
            sync_healthy: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            revocation_generation: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                persisted_generation,
            )),
        })
    }

    pub(super) fn read_state(&self) -> std::sync::RwLockReadGuard<'_, KeyState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, KeyState> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn invalid_decoding_key_error() -> jsonwebtoken::errors::Error {
    jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::InvalidToken)
}
