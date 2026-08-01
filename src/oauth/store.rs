use redis::{AsyncCommands, Client, Script};
use thiserror::Error;

use super::code::{AUTHORIZATION_CODE_TTL_SECONDS, AuthorizationCode};

#[derive(Clone)]
pub struct AuthorizationCodeStore {
    client: Client,
}

#[derive(Debug, Error)]
pub enum AuthorizationCodeStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("authorization code serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl AuthorizationCodeStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn save(&self, code: &AuthorizationCode) -> Result<(), AuthorizationCodeStoreError> {
        self.save_with_ttl(code, AUTHORIZATION_CODE_TTL_SECONDS)
            .await
    }

    pub async fn restore(
        &self,
        code: &AuthorizationCode,
        ttl_seconds: u64,
    ) -> Result<(), AuthorizationCodeStoreError> {
        self.save_with_ttl(code, ttl_seconds).await
    }

    async fn save_with_ttl(
        &self,
        code: &AuthorizationCode,
        ttl_seconds: u64,
    ) -> Result<(), AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(code)?;
        let _: () = connection
            .set_ex(Self::key(&code.value), payload, ttl_seconds.max(1))
            .await?;
        Ok(())
    }

    pub async fn take(
        &self,
        value: &str,
    ) -> Result<Option<AuthorizationCode>, AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(Self::key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationCodeStoreError::from)
    }

    pub async fn find(
        &self,
        value: &str,
    ) -> Result<Option<AuthorizationCode>, AuthorizationCodeStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::key(value)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationCodeStoreError::from)
    }

    pub async fn take_if_matches(
        &self,
        value: &str,
        code: &AuthorizationCode,
    ) -> Result<bool, AuthorizationCodeStoreError> {
        let expected = serde_json::to_string(code)?;
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
        format!("chenxing:oauth:code:{value}")
    }
}
