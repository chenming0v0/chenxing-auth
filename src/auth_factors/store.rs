use redis::{AsyncCommands, Script};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::{FactorMethod, LoginTicket};
use crate::{redis_client::RedisClient, users::domain::UserId};

const LOGIN_TICKET_PREFIX: &str = "chenxing:auth:login-ticket:";
const TOTP_REPLAY_PREFIX: &str = "chenxing:auth:totp-used:";
const TOTP_REPLAY_TTL_SECONDS: u64 = 120;
const CLAIM_TOTP_STEP_SCRIPT: &str =
    "if redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then return 1 else return 0 end";
const TAKE_LOGIN_TICKET_IF_HOLDER_SCRIPT: &str = r#"
local payload = redis.call('GET', KEYS[1])
if not payload then return nil end
local ticket = cjson.decode(payload)
if ticket['holder_hash'] ~= ARGV[1] then return nil end
redis.call('DEL', KEYS[1])
return payload
"#;

#[derive(Clone)]
pub struct LoginTicketStore {
    client: RedisClient,
    metadata: Option<crate::sqlx::PgPool>,
}

#[derive(Debug, Error)]
pub enum LoginTicketStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
    #[error("login ticket serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl LoginTicketStore {
    pub fn new(client: impl Into<RedisClient>) -> Self {
        Self {
            client: client.into(),
            metadata: None,
        }
    }

    pub fn new_with_pool(client: impl Into<RedisClient>, metadata: crate::sqlx::PgPool) -> Self {
        Self {
            client: client.into(),
            metadata: Some(metadata),
        }
    }

    /// Compatibility constructor for direct store users. HTTP-issued tickets
    /// must use `create_with_epoch_and_holder`; an unbound ticket is not
    /// accepted by `find_for_holder` or `take_for_holder`.
    pub async fn create(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        self.create_with_epoch(user_id, methods, 0).await
    }

    pub async fn create_with_epoch(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        session_epoch: i64,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        let ticket_id = Uuid::new_v4().to_string();
        let ticket = LoginTicket::new_with_epoch(user_id, methods, session_epoch);
        self.save(&ticket_id, &ticket).await?;
        Ok((ticket_id, ticket))
    }

    pub async fn create_with_holder(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        holder_hash: String,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        self.create_with_epoch_and_holder(user_id, methods, 0, holder_hash)
            .await
    }

    pub async fn create_with_epoch_and_holder(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
        session_epoch: i64,
        holder_hash: String,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        let ticket_id = Uuid::new_v4().to_string();
        let ticket = LoginTicket::new_with_epoch_and_holder(
            user_id,
            methods,
            session_epoch,
            Some(holder_hash),
        );
        self.save(&ticket_id, &ticket).await?;
        Ok((ticket_id, ticket))
    }

    pub async fn save(
        &self,
        ticket_id: &str,
        ticket: &LoginTicket,
    ) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&ticket)?;
        let _: () = connection
            .set_ex(
                Self::key(ticket_id),
                payload,
                LoginTicket::TTL.whole_seconds() as u64,
            )
            .await?;
        Ok(())
    }

    async fn find(
        &self,
        ticket_id: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        self.read(ticket_id, false).await
    }

    pub async fn find_for_holder(
        &self,
        ticket_id: &str,
        holder_hash: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        Ok(self
            .find(ticket_id)
            .await?
            .filter(|ticket| ticket.matches_holder_hash(holder_hash)))
    }

    pub async fn take_for_holder(
        &self,
        ticket_id: &str,
        holder_hash: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = Script::new(TAKE_LOGIN_TICKET_IF_HOLDER_SCRIPT)
            .key(Self::key(ticket_id))
            .arg(holder_hash)
            .invoke_async(&mut connection)
            .await?;
        self.decode_ticket_payload(payload).await
    }

    pub async fn restore(
        &self,
        ticket_id: &str,
        ticket: LoginTicket,
    ) -> Result<(), LoginTicketStoreError> {
        let ttl = (ticket.expires_at - OffsetDateTime::now_utc()).whole_seconds();
        if ttl <= 0 {
            return Ok(());
        }
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(&ticket)?;
        let _: () = connection
            .set_ex(Self::key(ticket_id), payload, ttl as u64)
            .await?;
        Ok(())
    }

    async fn read(
        &self,
        ticket_id: &str,
        consume: bool,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = if consume {
            connection.get_del(Self::key(ticket_id)).await?
        } else {
            connection.get(Self::key(ticket_id)).await?
        };
        self.decode_ticket_payload(payload).await
    }

    async fn decode_ticket_payload(
        &self,
        payload: Option<String>,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        let ticket: Option<LoginTicket> = payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)?;
        let Some(ticket) = ticket else {
            return Ok(None);
        };
        if let Some(pool) = &self.metadata {
            let current_epoch: Option<i64> =
                crate::sqlx::query_scalar("SELECT session_epoch FROM users WHERE id = $1")
                    .bind(ticket.user_id)
                    .fetch_optional(pool)
                    .await?;
            if current_epoch != Some(ticket.session_epoch) {
                return Ok(None);
            }
        }
        Ok(Some(ticket))
    }

    pub fn key(ticket_id: &str) -> String {
        format!("{LOGIN_TICKET_PREFIX}{ticket_id}")
    }

    pub async fn take_json<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get_del(key).await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)
    }

    pub async fn find_json<T: DeserializeOwned>(
        &self,
        key: &str,
    ) -> Result<Option<T>, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(key).await?;
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)
    }

    pub async fn save_json<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl_seconds: u64,
    ) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(value)?;
        let _: () = connection.set_ex(key, payload, ttl_seconds).await?;
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(key).await?;
        Ok(())
    }

    pub async fn claim_totp_timestep(
        &self,
        user_id: UserId,
        timestep: u64,
    ) -> Result<bool, LoginTicketStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let claimed: i64 = Script::new(CLAIM_TOTP_STEP_SCRIPT)
            .key(Self::totp_replay_key(user_id, timestep))
            .arg(TOTP_REPLAY_TTL_SECONDS)
            .invoke_async(&mut connection)
            .await?;
        Ok(claimed == 1)
    }

    pub fn totp_replay_key(user_id: UserId, timestep: u64) -> String {
        format!("{TOTP_REPLAY_PREFIX}{user_id}:{timestep}")
    }
}
