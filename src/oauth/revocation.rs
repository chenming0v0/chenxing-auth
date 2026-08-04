use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Client};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
        let _: () = connection.set(Self::consent_key(user_id, client_id), "1").await?;
        Ok(())
    }

    pub async fn is_consent_revoked(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<bool, TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        Ok(connection.exists(Self::consent_key(user_id, client_id)).await?)
    }

    pub async fn clear_consent(
        &self,
        user_id: &str,
        client_id: &str,
    ) -> Result<(), TokenRevocationError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(Self::consent_key(user_id, client_id)).await?;
        Ok(())
    }

    fn key(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        format!("chenxing:oauth:revoked:{}", URL_SAFE_NO_PAD.encode(digest))
    }

    fn consent_key(user_id: &str, client_id: &str) -> String {
        let binding = format!("{user_id}:{client_id}");
        let digest = Sha256::digest(binding.as_bytes());
        format!("chenxing:oauth:consent-revoked:{}", URL_SAFE_NO_PAD.encode(digest))
    }
}
