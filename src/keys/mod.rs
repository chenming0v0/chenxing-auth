//! JWK/JWKS 密钥的内存权威状态与协议读路径。
//!
//! 磁盘副作用拆到三个子模块，本文件保留状态类型、错误类型和模块聚合：
//! `persistence` 负责目录布局与文件读写，`rotation` 与 `revocation` 是持锁写入，
//! `sync` 是磁盘到内存的后台同步，`manager` 承载 KeyManager 的生命周期与读访问。
//! 材料生命周期与“最近在役”选择等纯领域规则在 `material`。
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{KeyPair, KeySize},
};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use pkcs8::PrivateKeyInfo;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::atomic::AtomicBool,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};
use thiserror::Error;
use tokio::sync::Notify;
use zeroize::Zeroizing;

mod activation;
mod journal;
mod manager;
mod material;
mod persistence;
mod prune;
mod retirement;
mod revocation;
mod rotation;
mod signing;
mod sync;

use activation::PendingPublishedKey;
use material::{KeyMaterial, PrivateKeyDer, compare_recency, key_material, newest_key_id};

pub use activation::{
    DEFAULT_KEY_ACTIVATION_DELAY_SECONDS, JWKS_CACHE_MAX_AGE_SECONDS,
    MAX_KEY_ACTIVATION_DELAY_SECONDS,
};
pub use signing::ActiveSigningKey;
pub use sync::{DEFAULT_KEY_SYNC_INTERVAL, KeySyncOutcome, MINIMUM_KEY_SYNC_INTERVAL};

pub const DEFAULT_KEY_RETENTION_SECONDS: u64 = 604_800;

/// 跨实例时钟偏差容忍（秒）的默认值（Issue #316）。
///
/// `retired_at` 由退役实例的时钟写入，保留窗口判断却发生在当前加载实例的时钟上。
/// 时钟偏快的实例会把 `now - retired_at` 算大，在真实窗口关闭前就判定过期并删除
/// 共享目录里的密钥文件——不可逆，且影响所有实例。该容忍值让窗口关闭边界变成
/// `retired_at + retention + skew_allowance`，快钟实例至多**晚**删、绝不提前删。
/// 默认 1 小时：NTP 同步的实例间偏差在秒级，1 小时覆盖全部现实部署，代价只是
/// 旧私钥多驻留 1/168 个默认窗口。
pub const DEFAULT_KEY_RETENTION_SKEW_ALLOWANCE_SECONDS: u64 = 3_600;

/// 签名密钥的内存权威副本。
///
/// 请求热路径（签发、验证、JWKS）只读 `state` 这一份内存快照，绝不在请求线程里
/// 触碰密钥目录：密钥目录锁是 flock，锁归属是 open file description，同一进程内
/// 不同 fd 之间同样互斥，把 reload 放进热路径会让两个并发请求互相抢锁并各自失败
/// （Issue #257）。磁盘一致性由 `run_disk_sync_worker` 的后台任务负责，
/// 轮换和吊销继续在 `spawn_blocking` 里持有目录锁独占写入。
#[derive(Clone)]
pub struct KeyManager {
    state: Arc<RwLock<KeyState>>,
    rotation_lock: Arc<Mutex<()>>,
    /// 热路径遇到未知 `kid` 时的提示通道，唤醒后台同步任务提前对齐磁盘快照。
    ///
    /// 通道只承载“该同步了”这一个事实，不携带数据；后台任务自带最小间隔，
    /// 因此伪造 `kid` 的请求无法把提示放大成任意频率的磁盘 IO。
    resync_hint: Arc<Notify>,
    /// 共享目录同步异常或尚未证明已观察到最新吊销代际时停止签发。
    sync_healthy: Arc<AtomicBool>,
    /// 最近一次成功同步/本实例吊销提交后观察到的共享吊销代际。
    revocation_generation: Arc<std::sync::atomic::AtomicU64>,
}

struct KeyState {
    directory: Option<PathBuf>,
    retention: Duration,
    /// 跨实例时钟偏差容忍（Issue #316）：窗口关闭边界是
    /// `retired_at + retention + skew_allowance`，保证时钟偏快的实例不会在真实
    /// 保留窗口结束前删除共享密钥文件。
    skew_allowance: Duration,
    /// 新公钥进入 JWKS 之后、接管签发之前必须等待的时间（Issue #454）。
    /// 已落盘的 `activate_at` 优先于这个值，因此中途改配置不会改写进行中的轮换。
    activation_delay: Duration,
    active_key_id: String,
    active_encoding_key: EncodingKey,
    private_materials: BTreeMap<String, KeyMaterial>,
    verification_keys: BTreeMap<String, DecodingKey>,
    jwks: JwkSet,
    /// 已发布、尚未接管签发的密钥。`None` 表示没有进行中的 publish→active 过渡。
    pending: Option<PendingPublishedKey>,
}

impl KeyState {
    /// 判断磁盘快照是否与当前内存快照等价。
    ///
    /// 比较 `kid` 集合、active `kid` 和每个已知 `kid` 的材料字节：`kid` 在生成时随机
    /// 分配，但共享目录中的文件可能被替换；相同 `kid` 只有在材料仍一致时才算同一快照。
    /// 私钥字节只在内存快照之间做等值比较，不写入日志或对外暴露。
    fn matches_disk_snapshot(
        &self,
        active_key_id: &str,
        materials: &BTreeMap<String, KeyMaterial>,
        pending_key_id: Option<&str>,
    ) -> bool {
        self.active_key_id == active_key_id
            && self.private_materials.keys().eq(materials.keys())
            && self.private_materials.iter().all(|(key_id, material)| {
                materials
                    .get(key_id)
                    .is_some_and(|other| material.der.as_slice() == other.der.as_slice())
            })
            && self.pending.as_ref().map(|pending| pending.key_id.as_str()) == pending_key_id
    }

    fn has_replaced_materials(&self, materials: &BTreeMap<String, KeyMaterial>) -> bool {
        self.private_materials.iter().any(|(key_id, material)| {
            materials
                .get(key_id)
                .is_some_and(|other| material.der.as_slice() != other.der.as_slice())
        })
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
    #[error("persisted active key material is missing")]
    MissingActiveKeyMaterial,
    #[error("requested signing key is not published")]
    UnknownKeyId,
    #[error("key rotation worker failed")]
    RotationWorker,
    #[error("key operation worker failed")]
    KeyWorker,
    #[error("persisted key material was replaced for an existing key id")]
    MaterialReplaced,
    #[error("persisted revocation generation is invalid")]
    InvalidRevocationGeneration,
    #[error("cannot revoke the active signing key without another valid signing key")]
    NoActiveKeyReplacement,
}

fn build_key_state(
    directory: Option<PathBuf>,
    retention: Duration,
    skew_allowance: Duration,
    activation_delay: Duration,
    active_key_id: String,
    private_materials: BTreeMap<String, KeyMaterial>,
    pending: Option<PendingPublishedKey>,
) -> Result<KeyState, KeyManagerError> {
    persistence::validate_key_id(&active_key_id)?;
    if let Some(pending) = pending.as_ref() {
        persistence::validate_key_id(&pending.key_id)?;
        if !private_materials.contains_key(&pending.key_id) {
            return Err(KeyManagerError::InvalidKeyId);
        }
    }
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
        skew_allowance,
        activation_delay,
        active_key_id,
        active_encoding_key: EncodingKey::from_rsa_der(active_der),
        private_materials,
        verification_keys,
        jwks: JwkSet { keys: jwks },
        pending,
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod rotation_tests;

#[cfg(test)]
mod revocation_tests;
