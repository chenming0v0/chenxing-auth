use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::consent_cache::ConsentStateCache;
use crate::consents::repository::PgConsentRepository;
use crate::redis_client::RedisClient;
use crate::sqlx::PgPool;

/// Access Token 与同意撤销的统一入口。
///
/// **两类撤销的存储策略不同**：
/// - Access Token 撤销只需 Redis：token 生命周期短，Redis 丢标记的最坏后果被
///   token 自身的过期时间兜住，TTL 按 token 剩余寿命设置。
/// - 同意撤销的权威事实在 PostgreSQL 的 `user_consents.revoked_at`
///   （Issue #64），Redis 只是带版本的可失效缓存，逻辑全部在
///   [`ConsentStateCache`]（Issue #276）。
#[derive(Clone)]
pub struct TokenRevocationStore {
    client: RedisClient,
    consent_states: ConsentStateCache,
}

#[derive(Debug, Error)]
pub enum TokenRevocationError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl TokenRevocationStore {
    /// 创建仅缓存模式的撤销存储。
    ///
    /// access token 撤销（`revoke` / `is_revoked` / `remove`）本就只需要 Redis。
    ///
    /// 但同意撤销（`is_consent_revoked`）在这个模式下**没有**数据库回源，
    /// 因此不适用于生产环境；生产环境必须使用
    /// [`TokenRevocationStore::new_with_pool`]。
    pub fn new(client: impl Into<RedisClient>) -> Self {
        let client = client.into();
        Self {
            consent_states: ConsentStateCache::new(client.clone(), None),
            client,
        }
    }

    /// 创建带数据库回源的撤销存储（生产环境，Issue #64 要求）。
    ///
    /// `is_consent_revoked` 在 Redis 缓存未给出「已撤销」结论时查询
    /// `user_consents.revoked_at` 作为权威判定，并回填缓存。
    pub fn new_with_pool(client: impl Into<RedisClient>, pool: PgPool) -> Self {
        let client = client.into();
        Self {
            consent_states: ConsentStateCache::new(
                client.clone(),
                Some(PgConsentRepository::new(pool)),
            ),
            client,
        }
    }

    pub async fn revoke(&self, token: &str, ttl_seconds: u64) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .set_ex(Self::key(token), "1", ttl_seconds.max(1))
            .await?;
        Ok(())
    }

    pub async fn is_revoked(&self, token: &str) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        Ok(connection.exists(Self::key(token)).await?)
    }

    pub async fn remove(&self, token: &str) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(Self::key(token)).await?;
        Ok(())
    }

    /// 写入同意撤销的缓存结论。
    ///
    /// **仅写缓存**：撤销的权威事实由 `ConsentService::revoke_for_user` 写入
    /// `user_consents.revoked_at`（Issue #64）。因此本函数失败时调用方
    /// 只需告警，不必回滚——缓存缺失会在下次判定时回源补上。
    ///
    /// `version` 必须是那次数据库写入返回的 `state_version`。缓存更新是
    /// 版本化条件写：若缓存中已有更高版本（例如用户已经重新授权），
    /// 本次写入被拒绝并返回 `Ok(false)`，避免陈旧标记否决数据库的新状态
    /// （Issue #276）。
    pub async fn revoke_consent(
        &self,
        user_id: &str,
        client_id: &str,
        version: i64,
    ) -> Result<bool, TokenRevocationError> {
        self.consent_states
            .record_revoked(user_id, client_id, version)
            .await
    }

    /// 写入同意「已授权」的版本围栏。
    ///
    /// 该值不用于放行（放行由数据库的 `revoked_at IS NULL` 判定），只用于挡住
    /// 版本更低的迟到撤销写入。见 [`ConsentStateCache::record_active`]。
    pub async fn activate_consent(
        &self,
        user_id: &str,
        client_id: &str,
        version: i64,
    ) -> Result<bool, TokenRevocationError> {
        self.consent_states
            .record_active(user_id, client_id, version)
            .await
    }

    /// 检查用户对指定 client 的授权同意是否已被撤销。
    ///
    /// 见 [`ConsentStateCache::is_revoked`]：缓存只加速拒绝，放行始终回源权威库。
    pub async fn is_consent_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, TokenRevocationError> {
        self.consent_states.is_revoked(user_id, client_id).await
    }

    /// 按数据库权威状态同步同意缓存（重新授权 / 授权码签发路径）。
    ///
    /// 取代旧的 `clear_consent`：单纯删除键无法阻止一个迟到的撤销写入随后落盘，
    /// 写入带版本的「已授权」围栏才能挡住它（Issue #276）。
    pub async fn refresh_consent_cache(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        self.consent_states
            .refresh_from_database(user_id, client_id)
            .await
    }

    /// 无条件删除同意缓存键。
    ///
    /// 语义是「忘掉缓存」而不是「写入更新的结论」，因此不做版本比较。
    /// 生产路径不使用它：删除会丢掉版本围栏。测试用它模拟 Redis 数据丢失。
    pub async fn forget_consent_cache(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        self.consent_states.forget(user_id, client_id).await
    }

    fn key(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!("chenxing:oauth:revoked:{}", URL_SAFE_NO_PAD.encode(digest))
    }
}
