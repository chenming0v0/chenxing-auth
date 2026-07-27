use redis::{AsyncCommands, Client, Script};
use thiserror::Error;

use super::refresh::RefreshToken;

#[derive(Clone)]
pub struct RefreshTokenStore {
    client: Client,
}

#[derive(Debug, Error)]
pub enum RefreshTokenStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("refresh token serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl RefreshTokenStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn save(&self, token: &RefreshToken) -> Result<(), RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(token)?;
        let _: () = connection
            .set_ex(Self::key(&token.value), payload, 30 * 24 * 60 * 60)
            .await?;
        Ok(())
    }

    pub async fn take(&self, value: &str) -> Result<Option<RefreshToken>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(Self::key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(RefreshTokenStoreError::from)
    }

    pub async fn find(&self, value: &str) -> Result<Option<RefreshToken>, RefreshTokenStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(RefreshTokenStoreError::from)
    }

    pub async fn take_if_matches(
        &self,
        value: &str,
        token: &RefreshToken,
    ) -> Result<bool, RefreshTokenStoreError> {
        let expected = serde_json::to_string(token)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let deleted: i32 = Script::new(
            r#"local current = redis.call('GET', KEYS[1])
               if current == ARGV[1] then
                   return redis.call('DEL', KEYS[1])
               end
               return 0"#,
        )
        .key(Self::key(value))
        .arg(expected)
        .invoke_async(&mut connection)
        .await?;
        Ok(deleted == 1)
    }

    fn key(value: &str) -> String {
        format!("chenxing:oauth:refresh:{value}")
    }
}
