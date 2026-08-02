use redis::{AsyncCommands, Client, Script};
use thiserror::Error;

use super::consent::PendingAuthorization;

pub const PENDING_REQUEST_TTL_SECONDS: u64 = 600;
pub const MAX_PENDING_REQUESTS_PER_CLIENT: u64 = 20;
pub const MAX_PENDING_REQUESTS_GLOBAL: u64 = 1_000;

const PENDING_CAPACITY_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then return -1 end
local client_count = tonumber(redis.call('GET', KEYS[2]) or '0')
local global_count = tonumber(redis.call('GET', KEYS[3]) or '0')
if client_count >= tonumber(ARGV[3]) or global_count >= tonumber(ARGV[4]) then
    return 0
end
redis.call('SETEX', KEYS[1], ARGV[2], ARGV[1])
redis.call('INCR', KEYS[2])
redis.call('EXPIRE', KEYS[2], ARGV[2])
redis.call('INCR', KEYS[3])
redis.call('EXPIRE', KEYS[3], ARGV[2])
return 1
"#;

const PENDING_TAKE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then return nil end
redis.call('DEL', KEYS[1])
return current
"#;

const PENDING_REPLACE_SCRIPT: &str = r#"
local current = redis.call('GET', KEYS[1])
if current ~= ARGV[1] then return 0 end
redis.call('SETEX', KEYS[1], ARGV[3], ARGV[2])
return 1
"#;

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
            .set_ex(
                Self::key(&request.request_id),
                payload,
                PENDING_REQUEST_TTL_SECONDS,
            )
            .await?;
        Ok(())
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
            .arg(payload)
            .arg(PENDING_REQUEST_TTL_SECONDS)
            .arg(MAX_PENDING_REQUESTS_PER_CLIENT)
            .arg(MAX_PENDING_REQUESTS_GLOBAL)
            .invoke_async(&mut connection)
            .await?;
        Ok(result == 1)
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

    pub async fn take_if_matches(
        &self,
        request_id: &str,
        request: &PendingAuthorization,
    ) -> Result<Option<PendingAuthorization>, AuthorizationRequestStoreError> {
        let expected = serde_json::to_string(request)?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(PENDING_TAKE_SCRIPT)
            .key(Self::key(request_id))
            .arg(expected)
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
            .arg(expected)
            .arg(replacement)
            .arg(PENDING_REQUEST_TTL_SECONDS)
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
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationRequestStore, MAX_PENDING_REQUESTS_PER_CLIENT, PendingAuthorization};

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
        }
    }

    #[tokio::test]
    async fn pending_creation_enforces_per_client_capacity() {
        let store = store();
        let client_id = format!("pending-capacity-{}", uuid::Uuid::new_v4().simple());
        for index in 0..MAX_PENDING_REQUESTS_PER_CLIENT {
            let request = pending(format!("request-{index}"), &client_id);
            assert!(store.save_limited(&request).await.expect("save pending"));
        }
        let rejected = pending("request-over-capacity".to_owned(), &client_id);
        assert!(!store.save_limited(&rejected).await.expect("capacity check"));
    }

    #[tokio::test]
    async fn concurrent_pending_takes_have_one_winner() {
        let store = store();
        let request = pending(
            format!("pending-take-{}", uuid::Uuid::new_v4().simple()),
            "pending-take-client",
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
}
