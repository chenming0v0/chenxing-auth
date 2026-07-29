use redis::{AsyncCommands, Client};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const STATE_TTL_SECONDS: u64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalLoginState {
    pub state: String,
    pub provider_slug: String,
    pub request_id: Option<String>,
}

#[derive(Clone)]
pub struct ExternalLoginStateStore {
    client: Client,
}

#[derive(Debug, Error)]
pub enum ExternalLoginStateStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("state serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl ExternalLoginStateStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn save(
        &self,
        value: &ExternalLoginState,
    ) -> Result<(), ExternalLoginStateStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(value)?;
        let _: () = connection
            .set_ex(Self::key(&value.state), payload, STATE_TTL_SECONDS)
            .await?;
        Ok(())
    }

    pub async fn take(
        &self,
        state: &str,
    ) -> Result<Option<ExternalLoginState>, ExternalLoginStateStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(Self::key(state)).await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    fn key(state: &str) -> String {
        format!("chenxing:oauth:external-state:{state}")
    }
}
