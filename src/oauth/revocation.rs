use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::AsyncCommands;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::consents::repository::{ConsentRepository, PgConsentRepository};
use crate::redis_client::RedisClient;
use crate::sqlx::PgPool;

/// 同意撤销标记的 TTL（秒）。
///
/// 该标记用于在 Redis 中快速拦截已撤销同意的存量 refresh token 和 access token。
/// 数据库中的 `user_consents.revoked_at` 是权威事实源（Issue #64），
/// 此标记仅作为短期加速缓存。
///
/// **取值依据**：
/// - 必须 ≥ refresh token 的绝对最大可能寿命，确保所有存量凭据在标记过期前已自然失效。
/// - 当前 refresh token 使用 30 天滑动窗口（`refresh_store.rs` 的 `REFRESH_TOKEN_TTL_SECONDS`）。
/// - Issue #109 将引入绝对上限以终止无限轮转，但在该功能落地前，此处采用保守值 90 天（3 倍安全系数）。
/// - 90 天后，任何撤销前签发的 refresh token 在实际业务场景下均已过期，标记失效不影响安全性。
///
/// **后续改进**：
/// - Issue #109 落地后，应从配置读取 refresh token 绝对上限，并将此 TTL 设为该上限 + 小幅缓冲（如 +7 天）。
const CONSENT_REVOCATION_TTL_SECONDS: u64 = 90 * 24 * 60 * 60;

#[derive(Clone)]
pub struct TokenRevocationStore {
    client: RedisClient,
    /// 同意撤销的权威数据源（Issue #64：数据库为真，Redis 为缓存）。
    ///
    /// 依赖 `repository` 而不是 `ConsentService`：撤销存储属于基础设施层，
    /// 向上依赖应用层会形成反向依赖。这里只需要存储边界的一个读方法。
    ///
    /// `None` 表示仅缓存模式（见 [`TokenRevocationStore::new`]）：
    /// `is_consent_revoked` 不做数据库回源，仅按 Redis 结论返回。
    consents: Option<PgConsentRepository>,
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
    /// access token 撤销（`revoke` / `is_revoked` / `remove`）本就只需要 Redis：
    /// access token 生命周期短，Redis 丢标记的最坏后果被 token 自身的过期时间兜住。
    ///
    /// 但同意撤销（`is_consent_revoked`）在这个模式下**没有**数据库回源，
    /// 因此不适用于生产环境；生产环境必须使用
    /// [`TokenRevocationStore::new_with_pool`]。
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            consents: None,
        }
    }

    /// 创建带数据库回源的撤销存储（生产环境，Issue #64 要求）。
    ///
    /// `is_consent_revoked` 在 Redis 缓存未命中时查询
    /// `user_consents.revoked_at` 作为权威判定，并回填缓存。
    pub fn new_with_pool(client: impl Into<RedisClient>, pool: PgPool) -> Self {
        Self {
            client: client.into(),
            consents: Some(PgConsentRepository::new(pool)),
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

    /// 写入同意撤销的缓存标记。
    ///
    /// **仅写缓存**：撤销的权威事实由 `ConsentService::revoke_for_user` 写入
    /// `user_consents.revoked_at`（Issue #64）。因此本函数失败时调用方
    /// 只需告警，不必回滚——缓存缺失会在下次判定时回源补上。
    ///
    /// 绑定 TTL（90 天）而非无限期 SET：超出窗口后所有存量凭据均已自然过期，
    /// 缓存键自动回收，避免键数量随「用户 × Client」撤销组合单调递增。
    pub async fn revoke_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .set_ex(
                Self::consent_key(user_id, client_id),
                "1",
                CONSENT_REVOCATION_TTL_SECONDS,
            )
            .await?;
        Ok(())
    }

    /// 检查用户对指定 client 的授权同意是否已被撤销。
    ///
    /// **判定流程**（Issue #64：数据库为权威，Redis 为可失效缓存）：
    /// 1. 读 Redis 缓存：键存在即确定「已撤销」，短路返回。
    /// 2. 键不存在无法区分「从未撤销」和「缓存未回填/已过期」，因此回源查数据库。
    /// 3. 回源结果为「已撤销」时回填缓存；「未撤销」刻意不缓存，
    ///    避免负缓存推迟后续撤销的生效时间。
    ///
    /// 仅缓存模式（见 [`TokenRevocationStore::new`]）跳过第 2、3 步。
    ///
    /// **fail-secure 取舍**：
    /// - Redis 故障：降级回源，不向调用方报错。缓存不可用不该让认证请求失败。
    /// - 数据库故障：返回 `Err(Database(..))`。调用方（`token_handlers`、`userinfo`）
    ///   已把错误映射为 503 temporarily_unavailable，因此既不会放行一个可能已撤销的
    ///   授权，也不会把抖动谎报成 `invalid_grant`。把错误上抛而不是就地判成「已撤销」，
    ///   是因为调用方能区分这两种情况，让它决定比在这里硬编码策略更准确。
    pub async fn is_consent_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, TokenRevocationError> {
        let key = Self::consent_key(user_id, client_id);

        // 第一步：读缓存。缓存里存在标记就是确定的「已撤销」，可以直接短路。
        // Redis 故障不在这里抛错：撤销判定的权威在数据库，缓存不可用只应降级为回源，
        // 不能因为缓存故障就把请求判成失败。
        match self.consent_cache_hit(&key).await {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(cache_error) => {
                tracing::warn!(
                    error = %cache_error,
                    "consent revocation cache unavailable, falling back to database"
                );
            }
        }

        // 第二步：没有权威数据源时（仅缓存模式，见 `new`），只能按缓存结论返回。
        let Some(consents) = &self.consents else {
            return Ok(false);
        };

        // 第三步：回源数据库。缓存中键不存在有两种可能——从未撤销，或缓存尚未回填/已过期，
        // 二者无法在 Redis 侧区分，因此必须查权威源才能给出「未撤销」的结论。
        //
        // fail-secure：这里的 `?` 会把数据库错误交给调用方（token_handlers / userinfo），
        // 它们映射为 503 temporarily_unavailable。既不放行可能已撤销的授权，
        // 也不把一次数据库抖动谎报成「已撤销」而让用户看到无法解释的 invalid_grant。
        let Ok(user_id) = user_id.parse::<crate::users::domain::UserId>() else {
            // user_id 不是合法用户标识，不可能存在对应的同意记录
            return Ok(false);
        };
        let revoked = consents.is_revoked(user_id, client_id).await?;

        // 第四步：只回填「已撤销」这一侧。未撤销状态刻意不缓存——否则用户撤销后
        // 需要等负缓存过期才能生效，而撤销必须立即起效。
        if revoked {
            self.cache_consent_revoked(&key).await;
        }
        Ok(revoked)
    }

    /// 读同意撤销缓存；键存在即为已撤销。
    async fn consent_cache_hit(&self, key: &str) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        Ok(connection.exists(key).await?)
    }

    /// 回填同意撤销缓存（best-effort）。
    ///
    /// 写失败只记 warn：数据库已持有权威事实，缓存缺失只会让下次判定再回源一次，
    /// 不影响正确性。
    async fn cache_consent_revoked(&self, key: &str) {
        if let Err(cache_error) = self.write_consent_cache(key).await {
            tracing::warn!(
                error = %cache_error,
                "failed to back-fill consent revocation cache from database"
            );
        }
    }

    async fn write_consent_cache(&self, key: &str) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .set_ex(key, "1", CONSENT_REVOCATION_TTL_SECONDS)
            .await?;
        Ok(())
    }

    /// 清除同意撤销的缓存标记（用户重新授权时调用）。
    ///
    /// **仅清缓存**。权威侧的 `revoked_at` 由 `ConsentService::save` 的 upsert
    /// 在同一次重新授权中清回 NULL，且发生在本函数之前
    /// （`ui_handlers::decide_authorization_request` 先 `save` 再签发授权码）。
    /// 顺序很关键：若先清缓存后清库，中间的回源查询会把刚重新授予的同意判成已撤销。
    pub async fn clear_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection
            .del(Self::consent_key(user_id, client_id))
            .await?;
        Ok(())
    }

    fn key(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!("chenxing:oauth:revoked:{}", URL_SAFE_NO_PAD.encode(digest))
    }

    fn consent_key(user_id: &str, client_id: &str) -> String {
        let binding = format!("{user_id}:{client_id}");
        let digest = Sha256::digest(binding.as_bytes());
        format!(
            "chenxing:oauth:consent-revoked:{}",
            URL_SAFE_NO_PAD.encode(digest)
        )
    }
}
