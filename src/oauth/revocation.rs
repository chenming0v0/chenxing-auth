use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Client};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 同意撤销标记的 TTL（秒）。
///
/// 该标记用于在 Redis 中快速拦截已撤销同意的存量 refresh token 和 access token。
/// 数据库中的 `consents` 表是权威事实源，此标记仅作为短期加速缓存。
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
    client: Client,
}

#[derive(Debug, Error)]
pub enum TokenRevocationError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
}

impl TokenRevocationStore {
    pub fn new(client: Client) -> Self {
        Self { client }
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

    pub async fn revoke_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        // 绑定 TTL 而不是无限期 SET：撤销的权威事实是 `consents` 表行删除，
        // Redis 标记只负责在存量凭据的有效窗口内加速失效，超过窗口后键必须自动回收，
        // 否则键数量会随「用户 × Client」撤销组合单调递增，永不释放。
        let _: () = connection
            .set_ex(
                Self::consent_key(user_id, client_id),
                "1",
                CONSENT_REVOCATION_TTL_SECONDS,
            )
            .await?;
        Ok(())
    }

    pub async fn is_consent_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        Ok(connection
            .exists(Self::consent_key(user_id, client_id))
            .await?)
    }

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
