use redis::{AsyncCommands, Script};
use thiserror::Error;

use super::consent::PendingAuthorization;
use super::request_store_scripts::{
    PENDING_CAPACITY_SCRIPT, PENDING_REPLACE_SCRIPT, PENDING_TAKE_IF_MATCHES_SCRIPT,
    PENDING_TAKE_SCRIPT,
};
use crate::redis_client::RedisClient;

pub const PENDING_REQUEST_TTL_SECONDS: u64 = 600;
pub const MAX_PENDING_REQUESTS_PER_CLIENT: u64 = 20;
pub const MAX_PENDING_REQUESTS_GLOBAL: u64 = 1_000;

#[derive(Clone)]
pub struct AuthorizationRequestStore {
    client: RedisClient,
}

#[derive(Debug, Error)]
pub enum AuthorizationRequestStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("authorization request serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("pending authorization request capacity exceeded")]
    CapacityExceeded,
}

impl AuthorizationRequestStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
        }
    }

    pub async fn save(
        &self,
        request: &PendingAuthorization,
    ) -> Result<(), AuthorizationRequestStoreError> {
        if self.save_limited(request).await? {
            Ok(())
        } else {
            Err(AuthorizationRequestStoreError::CapacityExceeded)
        }
    }

    pub async fn save_limited(
        &self,
        request: &PendingAuthorization,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let payload = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let result: i64 = Script::new(PENDING_CAPACITY_SCRIPT)
            .key(Self::key(&request.request_id))
            .key(Self::client_capacity_key(&request.client_id))
            .key(Self::global_capacity_key())
            .key(Self::client_index_key(&request.client_id))
            .key(Self::global_index_key())
            .key(Self::global_expiry_key())
            .arg(payload)
            .arg(PENDING_REQUEST_TTL_SECONDS)
            .arg(MAX_PENDING_REQUESTS_PER_CLIENT)
            .arg(MAX_PENDING_REQUESTS_GLOBAL)
            .arg(&request.client_id)
            .arg(&request.request_id)
            .invoke_async(&mut connection)
            .await?;
        Ok(result == 1)
    }

    pub async fn take(
        &self,
        request_id: &str,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(PENDING_TAKE_SCRIPT)
            .key(Self::key(request_id))
            .key(Self::global_index_key())
            .key(Self::global_capacity_key())
            .key(Self::global_expiry_key())
            .arg(request_id)
            .arg(PENDING_REQUEST_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    pub async fn take_if_matches(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(PENDING_TAKE_IF_MATCHES_SCRIPT)
            .key(Self::key(request_id))
            .key(Self::global_index_key())
            .key(Self::global_capacity_key())
            .key(Self::global_expiry_key())
            .arg(expected)
            .arg(request_id)
            .arg(PENDING_REQUEST_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await?;
        payload
            .map(|payload| serde_json::from_str(&payload))
            .transpose()
            .map_err(AuthorizationRequestStoreError::from)
    }

    pub async fn replace_if_matches(
        &self,
        request_id: &str,
        expected: &PendingAuthorization,
        replacement: &PendingAuthorization,
    ) -> Result<bool, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(expected)?;
        let replacement = serde_json::to_string(replacement)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let replaced: i64 = Script::new(PENDING_REPLACE_SCRIPT)
            .key(Self::key(request_id))
            .key(Self::global_index_key())
            .key(Self::global_capacity_key())
            .key(Self::global_expiry_key())
            .arg(expected)
            .arg(replacement)
            .arg(request_id)
            .arg(PENDING_REQUEST_TTL_SECONDS)
            .arg(MAX_PENDING_REQUESTS_PER_CLIENT)
            .arg(MAX_PENDING_REQUESTS_GLOBAL)
            .invoke_async(&mut connection)
            .await?;
        Ok(replaced == 1)
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

    fn client_capacity_key(client_id: &str) -> String {
        format!("chenxing:oauth:pending:client:{client_id}")
    }

    fn global_capacity_key() -> &'static str {
        "chenxing:oauth:pending:global"
    }

    fn client_index_key(client_id: &str) -> String {
        format!("chenxing:oauth:pending:client-requests:{client_id}")
    }

    fn global_index_key() -> &'static str {
        "chenxing:oauth:pending:index"
    }

    fn global_expiry_key() -> &'static str {
        "chenxing:oauth:pending:expiry"
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationRequestStore, MAX_PENDING_REQUESTS_PER_CLIENT, PendingAuthorization};
    use redis::AsyncCommands;

    fn store() -> AuthorizationRequestStore {
        let url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        AuthorizationRequestStore::new(redis::Client::open(url).expect("Redis URL"))
    }

    fn pending(request_id: String, client_id: &str) -> PendingAuthorization {
        PendingAuthorization {
            request_id,
            client_id: client_id.to_owned(),
            redirect_uri: "https://client.example/callback".to_owned(),
            scope: "openid".to_owned(),
            state: "state".to_owned(),
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: "S256".to_owned(),
            session_id: None,
            holder_hash: None,
        }
    }

    #[tokio::test]
    async fn pending_creation_enforces_per_client_capacity() {
        let store = store();
        let client_id = format!("pending-capacity-{}", uuid::Uuid::new_v4().simple());
        for index in 0..MAX_PENDING_REQUESTS_PER_CLIENT {
            let request = pending(
                format!("request-{}-{index}", uuid::Uuid::new_v4().simple()),
                &client_id,
            );
            assert!(store.save_limited(&request).await.expect("save pending"));
            store
                .take(&request.request_id)
                .await
                .expect("cleanup pending request");
        }
        let requests: Vec<_> = (0..MAX_PENDING_REQUESTS_PER_CLIENT)
            .map(|index| pending(format!("request-full-{index}"), &client_id))
            .collect();
        for request in &requests {
            assert!(store.save_limited(request).await.expect("save pending"));
        }
        let rejected = pending(
            format!("request-over-capacity-{}", uuid::Uuid::new_v4().simple()),
            &client_id,
        );
        assert!(!store.save_limited(&rejected).await.expect("capacity check"));
        for request in requests {
            store
                .take(&request.request_id)
                .await
                .expect("cleanup pending request");
        }
    }

    #[tokio::test]
    async fn concurrent_pending_takes_have_one_winner() {
        let store = store();
        let request = pending(
            format!("pending-take-{}", uuid::Uuid::new_v4().simple()),
            &format!("pending-take-client-{}", uuid::Uuid::new_v4().simple()),
        );
        store.save(&request).await.expect("save pending");
        let first_store = store.clone();
        let second_store = store.clone();
        let (first, second) = tokio::join!(
            first_store.take_if_matches(&request.request_id, &request),
            second_store.take_if_matches(&request.request_id, &request),
        );
        let winners = [
            first.expect("first take").is_some(),
            second.expect("second take").is_some(),
        ]
        .into_iter()
        .filter(|won| *won)
        .count();
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn consuming_pending_releases_capacity_once() {
        let store = store();
        let client_id = format!("pending-release-{}", uuid::Uuid::new_v4().simple());
        let requests: Vec<_> = (0..MAX_PENDING_REQUESTS_PER_CLIENT)
            .map(|index| pending(format!("pending-release-{index}"), &client_id))
            .collect();
        for request in &requests {
            assert!(store.save_limited(request).await.expect("save pending"));
        }
        let consumed = store
            .take_if_matches(&requests[0].request_id, &requests[0])
            .await
            .expect("consume pending");
        assert!(consumed.is_some());
        assert!(
            store
                .take_if_matches(&requests[0].request_id, &requests[0])
                .await
                .expect("repeat pending consume")
                .is_none()
        );

        let replacement = pending(
            format!(
                "pending-release-replacement-{}",
                uuid::Uuid::new_v4().simple()
            ),
            &client_id,
        );
        assert!(
            store
                .save_limited(&replacement)
                .await
                .expect("reuse released capacity")
        );
        let rejected = pending(
            format!("pending-release-rejected-{}", uuid::Uuid::new_v4().simple()),
            &client_id,
        );
        assert!(!store.save_limited(&rejected).await.expect("capacity check"));
        for request in requests.into_iter().skip(1) {
            store
                .take(&request.request_id)
                .await
                .expect("cleanup pending request");
        }
        store
            .take(&replacement.request_id)
            .await
            .expect("cleanup replacement request");
    }

    #[tokio::test]
    async fn expired_pending_request_releases_capacity_when_processed() {
        let store = store();
        let client_id = format!("pending-expiry-{}", uuid::Uuid::new_v4().simple());
        let expired = pending(
            format!("pending-expired-{}", uuid::Uuid::new_v4().simple()),
            &client_id,
        );
        assert!(store.save_limited(&expired).await.expect("save pending"));
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_owned());
        let redis_client = redis::Client::open(redis_url).expect("Redis URL");
        let mut connection = redis_client
            .get_multiplexed_async_connection()
            .await
            .expect("Redis connection");
        // Redis owns this TTL clock; advancing Tokio time cannot expire a remote Redis key.
        let _: bool = connection
            .expire(format!("chenxing:oauth:request:{}", expired.request_id), 0)
            .await
            .expect("expire pending request");
        assert!(
            store
                .take(&expired.request_id)
                .await
                .expect("process expired request")
                .is_none()
        );

        let replacement = pending(
            format!(
                "pending-expiry-replacement-{}",
                uuid::Uuid::new_v4().simple()
            ),
            &client_id,
        );
        assert!(
            store
                .save_limited(&replacement)
                .await
                .expect("reuse expired capacity")
        );
        store
            .take(&replacement.request_id)
            .await
            .expect("cleanup replacement request");
    }
}
