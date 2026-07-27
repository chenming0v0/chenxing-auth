use std::time::Duration;

use redis::{AsyncCommands, Client};
use thiserror::Error;
use uuid::Uuid;

use super::domain::Session;

#[derive(Clone)]
pub struct SessionStore {
    client: Client,
    key_prefix: String,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl SessionStore {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
        }
    }

    pub async fn save(&self, session: &Session, ttl: Duration) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(session)?;
        let _: () = connection
            .set_ex(self.key(&session.id), payload, ttl.as_secs().max(1))
            .await?;
        Ok(())
    }

    pub async fn find(&self, id: Uuid) -> Result<Option<Session>, SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(&id)).await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(SessionStoreError::from)
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(self.key(&id)).await?;
        Ok(())
    }

    fn key(&self, id: &Uuid) -> String {
        format!("{}{id}", self.key_prefix)
    }
}
