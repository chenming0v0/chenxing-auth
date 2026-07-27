use redis::{AsyncCommands, Client};
use thiserror::Error;

use super::consent::PendingAuthorization;

#[derive(Clone)]
pub struct AuthorizationRequestStore {
    client: Client,
}

#[derive(Debug, Error)]
pub enum AuthorizationRequestStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("authorization request serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl AuthorizationRequestStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn save(
        &self,
        request: &PendingAuthorization,
    ) -> Result<(), AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(request)?;
        let _: () = connection
            .set_ex(Self::key(&request.request_id), payload, 600)
            .await?;
        Ok(())
    }

    pub async fn take(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(Self::key(request_id)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    pub async fn find(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(Self::key(request_id)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    fn key(request_id: &str) -> String {
        format!("chenxing:oauth:request:{request_id}")
    }
}
