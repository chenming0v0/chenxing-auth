use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use super::access_token_revocation::{PgAccessTokenRevocationRepository, TokenDigest};
use super::consent_cache::ConsentStateCache;
use crate::consents::repository::PgConsentRepository;
use crate::sqlx::PgPool;
use crate::{redis_client::RedisClient, redis_keyspace::RedisKeyspace};

/// Access Token 与同意撤销的统一入口。
///
/// **两类撤销的存储策略相同**：PostgreSQL 是权威事实，Redis 是可失效缓存。
///
/// - Access Token 撤销写入 `revoked_access_tokens`（Issue #656）。token 寿命短
///   并不能让 Redis 丢标记变成可接受的后果：JWT 在 `exp` 之前仍然可验证，
///   UserInfo 会把一个已撤销的令牌重新放行。Redis 未命中必须回源；回源失败
///   必须 fail-closed，不得当成「未撤销」。
/// - 同意撤销的权威事实在 PostgreSQL 的 `user_consents.revoked_at`
///   （Issue #64），Redis 只是带版本的可失效缓存，逻辑全部在
///   [`ConsentStateCache`]（Issue #276）。
#[derive(Clone)]
pub struct TokenRevocationStore {
    client: RedisClient,
    consent_states: ConsentStateCache,
    access_tokens: Option<PgAccessTokenRevocationRepository>,
    keyspace: RedisKeyspace,
}

#[derive(Debug, Error)]
pub enum TokenRevocationError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl TokenRevocationStore {
    fn from_parts(client: RedisClient, pool: Option<PgPool>, keyspace: RedisKeyspace) -> Self {
        Self {
            consent_states: ConsentStateCache::with_keyspace(
                client.clone(),
                pool.clone().map(PgConsentRepository::new),
                keyspace.clone(),
            ),
            access_tokens: pool.map(PgAccessTokenRevocationRepository::new),
            client,
            keyspace,
        }
    }

    /// 创建仅缓存模式的撤销存储。
    ///
    /// access token 撤销和同意撤销在这个模式下都**没有**数据库回源，
    /// 因此不适用于生产环境；生产环境必须使用
    /// [`TokenRevocationStore::new_with_pool`]。
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self::from_parts(client.into(), None, RedisKeyspace::default())
    }

    pub fn with_keyspace(client: impl Into<RedisClient>, keyspace: RedisKeyspace) -> Self {
        Self::from_parts(client.into(), None, keyspace)
    }

    /// 创建带数据库回源的撤销存储（生产环境，Issue #64 / #656）。
    ///
    /// Access token：Redis 未命中时查询 `revoked_access_tokens`。
    /// 同意：Redis 缓存未给出「已撤销」结论时查询 `user_consents.revoked_at`。
    pub fn new_with_pool(client: impl Into<RedisClient>, pool: PgPool) -> Self {
        Self::from_parts(client.into(), Some(pool), RedisKeyspace::default())
    }

    pub fn new_with_pool_and_keyspace(
        client: impl Into<RedisClient>,
        pool: PgPool,
        keyspace: RedisKeyspace,
    ) -> Self {
        Self::from_parts(client.into(), Some(pool), keyspace)
    }

    pub async fn revoke(&self, token: &str, ttl_seconds: u64) -> Result<(), TokenRevocationError> {
        let ttl_seconds = ttl_seconds.max(1);
        if let Some(store) = &self.access_tokens {
            store.record(&token_digest(token), ttl_seconds).await?;
            if let Err(cache_error) = self.cache_revoked(token, ttl_seconds).await {
                tracing::warn!(
                    error = %cache_error,
                    "access token revocation persisted; cache write failed and will be back-filled"
                );
            }
            return Ok(());
        }
        self.cache_revoked(token, ttl_seconds).await
    }

    pub async fn is_revoked(&self, token: &str) -> Result<bool, TokenRevocationError> {
        match self.cached_revocation(token).await {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(cache_error) => {
                if self.access_tokens.is_none() {
                    return Err(cache_error);
                }
                tracing::warn!(
                    error = %cache_error,
                    "access token revocation cache unavailable, falling back to database"
                );
            }
        }

        let Some(store) = &self.access_tokens else {
            return Ok(false);
        };
        // 回源失败必须传播：把数据库故障当成「未撤销」会让一个已吊销、JWT 仍
        // 未过期的 access token 重新通过 UserInfo（Issue #656）。
        let Some(expires_at) = store.lookup(&token_digest(token)).await? else {
            return Ok(false);
        };
        if let Err(cache_error) = self
            .cache_revoked(token, remaining_ttl_seconds(expires_at))
            .await
        {
            tracing::warn!(
                error = %cache_error,
                "access token revocation cache back-fill failed"
            );
        }
        Ok(true)
    }

    pub async fn remove(&self, token: &str) -> Result<(), TokenRevocationError> {
        if let Some(store) = &self.access_tokens {
            store.remove(&token_digest(token)).await?;
        }
        self.forget_access_token_cache(token).await
    }

    /// 无条件删除 access-token 撤销的 Redis 标记。
    ///
    /// 语义是「忘掉缓存」而不是「撤销撤回」。生产路径不使用它：权威行仍在
    /// PostgreSQL。测试用它模拟 Redis 数据丢失。
    pub async fn forget_access_token_cache(&self, token: &str) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(self.key(token)).await?;
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

    async fn cached_revocation(&self, token: &str) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        Ok(connection.exists(self.key(token)).await?)
    }

    async fn cache_revoked(
        &self,
        token: &str,
        ttl_seconds: u64,
    ) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .set_ex(self.key(token), "1", ttl_seconds.max(1))
            .await?;
        Ok(())
    }

    fn key(&self, token: &str) -> String {
        self.keyspace.key(&format!(
            "chenxing:oauth:revoked:{}",
            URL_SAFE_NO_PAD.encode(token_digest(token))
        ))
    }
}

fn token_digest(token: &str) -> TokenDigest {
    Sha256::digest(token.as_bytes()).into()
}

fn remaining_ttl_seconds(expires_at: OffsetDateTime) -> u64 {
    let remaining = expires_at.unix_timestamp() - OffsetDateTime::now_utc().unix_timestamp();
    u64::try_from(remaining).unwrap_or(1).max(1)
}
