//! Session 存储边界。
//!
//! 本文件保留 `SessionStore` 结构体、错误类型、构造函数和共享工具方法。
//! 公开 API 在此调度到两条实现路径：
//!
//! - [`redis_only`]：无 Postgres 元数据时的纯 Redis 路径（开发 / 测试）。
//! - [`postgres`]：带 Postgres 权威记录的生产路径。
//!
//! `pub(crate)` 的 `lock_user_session_scope` 和 `revoke_all_for_user_in_transaction`
//! 在此 re-export，`users::repository` 的既有调用路径不变。

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;
use time::OffsetDateTime;

use super::{
    crypto,
    domain::{Session, SessionLookup, SessionPayload, SessionPolicy, session_token_hash_bytes},
};
use crate::{config::AuthEncryptionKeyRing, redis_client::RedisClient, users::domain::UserId};

mod postgres;
mod redis_only;

// 两个函数本体在 postgres 子模块，可见性保持 `pub(crate)`：
// `users::repository` 通过 `crate::sessions::store::...` 调用，路径不变。
// 这里必须用 `pub(crate) use` 而非 `pub use`——`pub use` 重导出 `pub(crate)` 条目
// 会触发 E0365。
pub(crate) use postgres::{lock_user_session_scope, revoke_all_for_user_in_transaction};

#[derive(Clone)]
pub struct SessionStore {
    pub(super) client: RedisClient,
    pub(super) key_prefix: String,
    pub(super) metadata: Option<crate::sqlx::PgPool>,
    pub(super) encryption_keys: Option<AuthEncryptionKeyRing>,
    pub(super) policy: SessionPolicy,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("session payload encryption failed")]
    PayloadEncryption,
    #[error("session payload decryption failed")]
    PayloadDecryption,
    #[error("session payload encoding failed")]
    PayloadEncoding,
    #[error("session metadata is unavailable")]
    MetadataUnavailable,
    #[error("session outbox record is invalid")]
    InvalidOutbox,
    #[error("session user id is invalid")]
    InvalidUserId,
    #[error("session user is not active")]
    UserDisabled,
    #[error("session user was not found")]
    UserNotFound,
    #[error("session was rejected by a revocation watermark")]
    SessionRevoked,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}

impl SessionStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: None,
            policy: SessionPolicy::default(),
        }
    }

    pub fn with_redis_key(client: impl Into<RedisClient>, encryption_key: [u8; 32]) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: Some(AuthEncryptionKeyRing::single(
                crate::config::AuthEncryptionKey::new(encryption_key),
            )),
            policy: SessionPolicy::default(),
        }
    }

    pub fn with_metadata_and_key(
        client: impl Into<RedisClient>,
        metadata: crate::sqlx::PgPool,
        encryption_key: [u8; 32],
    ) -> Self {
        Self::with_metadata_and_key_ring(
            client,
            metadata,
            AuthEncryptionKeyRing::single(crate::config::AuthEncryptionKey::new(encryption_key)),
        )
    }

    pub fn with_metadata_and_key_ring(
        client: impl Into<RedisClient>,
        metadata: crate::sqlx::PgPool,
        encryption_keys: AuthEncryptionKeyRing,
    ) -> Self {
        Self {
            client: client.into(),
            key_prefix: "chenxing:session:".to_owned(),
            metadata: Some(metadata),
            encryption_keys: Some(encryption_keys),
            policy: SessionPolicy::default(),
        }
    }

    pub fn with_session_policy(
        mut self,
        idle_timeout: Duration,
        max_concurrent_sessions: u64,
    ) -> Self {
        if !idle_timeout.is_zero()
            && time::Duration::try_from(idle_timeout).is_ok()
            && max_concurrent_sessions > 0
        {
            self.policy = SessionPolicy {
                absolute_ttl: self.policy.absolute_ttl,
                idle_timeout,
                max_concurrent_sessions,
            };
        }
        self
    }

    pub fn with_absolute_ttl(mut self, absolute_ttl: Duration) -> Self {
        if !absolute_ttl.is_zero() && time::Duration::try_from(absolute_ttl).is_ok() {
            self.policy.absolute_ttl = absolute_ttl;
        }
        self
    }

    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
        session.set_idle_timeout(self.policy.idle_timeout);
        if self.metadata.is_some() {
            postgres::save_with_metadata(self, session, ttl).await
        } else {
            redis_only::save_redis_only(self, session, ttl).await
        }
    }

    pub async fn find(&self, token: &str) -> Result<Option<Session>, SessionStoreError> {
        if self.metadata.is_some() {
            postgres::find_with_metadata(self, token).await
        } else {
            redis_only::find_redis_only(self, token).await
        }
    }

    /// Look up active session metadata without requiring or reconstructing the plaintext token.
    pub async fn find_by_token_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<SessionLookup>, SessionStoreError> {
        if self.metadata.is_some() {
            postgres::find_with_metadata_by_token_hash(self, token_hash).await
        } else {
            redis_only::find_redis_only_by_token_hash(self, token_hash).await
        }
    }

    pub async fn revoke(&self, token: &str) -> Result<(), SessionStoreError> {
        let hash = session_token_hash_bytes(token).to_vec();
        if self.metadata.is_none() {
            redis_only::revoke_redis_only(self, &hash).await
        } else {
            postgres::revoke_by_token_hash(self, &hash).await
        }
    }

    pub async fn list_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<SessionSummary>, SessionStoreError> {
        postgres::list_for_user(self, user_id).await
    }

    pub async fn revoke_for_user(
        &self,
        user_id: UserId,
        session_id: i64,
    ) -> Result<bool, SessionStoreError> {
        postgres::revoke_for_user(self, user_id, session_id).await
    }

    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<(), SessionStoreError> {
        if self.metadata.is_some() {
            postgres::revoke_all_for_user(self, user_id).await
        } else {
            redis_only::revoke_all_redis_only(self, user_id).await
        }
    }

    pub(super) fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        crypto::encrypt(keys, payload)
    }

    /// 解密并解析持久化载荷。
    ///
    /// 解密或解析失败返回 `Ok(None)`，由调用方按"会话不存在"处理，避免把密钥配置
    /// 问题和损坏数据变成可探测的错误差异。缺少密钥环属于配置错误，仍然返回 `Err`。
    ///
    /// 升级前写入的载荷含有 `token` 字段；`SessionPayload` 未标注
    /// `deny_unknown_fields`，serde 会忽略这个多余字段，因此历史数据继续可读。
    pub(super) fn decode_payload(
        &self,
        payload: &[u8],
    ) -> Result<Option<SessionPayload>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        Ok(crypto::decrypt(keys, payload)
            .ok()
            .and_then(|payload| serde_json::from_slice(&payload).ok()))
    }

    pub(super) fn key(&self, token: &str) -> String {
        self.key_hash(&session_token_hash_bytes(token))
    }

    pub(super) fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }

    pub(super) fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-epoch:{user_id}", self.key_prefix)
    }

    pub(super) fn redis_only_revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }

    pub(super) fn redis_only_token_revocation_key(&self, hash: &[u8]) -> String {
        format!(
            "{}revoked-token:{}",
            self.key_prefix,
            URL_SAFE_NO_PAD.encode(hash)
        )
    }

    pub(super) fn idle_timeout_interval(&self) -> time::Duration {
        time::Duration::seconds(
            i64::try_from(self.policy.idle_timeout.as_secs())
                .unwrap_or(i64::MAX)
                .max(1),
        )
    }

    pub(super) fn renewal_interval(&self) -> time::Duration {
        time::Duration::seconds(
            i64::try_from(self.policy.idle_timeout.as_secs() / 2)
                .unwrap_or(i64::MAX)
                .max(1),
        )
    }

    /// 撤销标记（单条 tombstone 与用户级水位）的存活时长。
    ///
    /// 取绝对 Session TTL 是安全的下限：任何会话键的存活窗口都不超过
    /// [`Self::redis_ttl_seconds`]，而后者同样被这个值封顶（见该函数注释），
    /// 因此"撤销标记先于被它拦截的会话键消失"不可能发生。
    pub(super) fn revocation_ttl_seconds(&self) -> u64 {
        self.policy.absolute_ttl.as_secs().max(1)
    }

    /// 会话键在 Redis 的存活秒数。
    ///
    /// 除了绝对过期与 idle 截止，这里还被 [`Self::revocation_ttl_seconds`] 封顶。
    /// 这一层封顶是撤销水位 TTL 的安全前提：水位在撤销时刻 `T` 写入并带上
    /// `EX = revocation_ttl`，而任何在 `T` 之前写入的会话键最晚也在
    /// `写入时刻 + revocation_ttl <= T + revocation_ttl` 过期。水位不会先于它
    /// 应当拦截的旧会话消失，旧会话也就不可能在水位过期后复活。
    /// 调用方传入的 `absolute_ttl` 只能收紧、不能放宽这个上限。
    pub(super) fn redis_ttl_seconds(
        &self,
        session: &Session,
        absolute_ttl: Duration,
        now: OffsetDateTime,
    ) -> u64 {
        let absolute = (session.expires_at - now).whole_seconds().max(1) as u64;
        let idle = session
            .idle_deadline()
            .map(|deadline| (deadline - now).whole_seconds().max(1) as u64)
            .unwrap_or(absolute);
        absolute
            .min(idle)
            .min(absolute_ttl.as_secs().max(1))
            .min(self.revocation_ttl_seconds())
    }
}

pub(super) fn timestamp_watermark(value: OffsetDateTime) -> i64 {
    value
        .unix_timestamp_nanos()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64
}
