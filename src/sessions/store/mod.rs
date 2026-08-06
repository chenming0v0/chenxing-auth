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
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use super::{
    crypto,
    domain::{Session, SessionPayload},
};
use crate::{
    config::AuthEncryptionKeyRing,
    redis_client::RedisClient,
    users::domain::UserId,
};

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
        }
    }

    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
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

    pub async fn revoke(&self, token: &str) -> Result<(), SessionStoreError> {
        let hash = Sha256::digest(token.as_bytes()).to_vec();
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
        self.key_hash(&Sha256::digest(token.as_bytes()))
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
}

pub(super) fn timestamp_watermark(value: OffsetDateTime) -> i64 {
    value
        .unix_timestamp_nanos()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64
}
