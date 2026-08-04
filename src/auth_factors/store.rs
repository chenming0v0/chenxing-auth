use redis::{AsyncCommands, Client};
use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use super::domain::{FactorMethod, LoginTicket};
use crate::users::domain::UserId;

const LOGIN_TICKET_PREFIX: &str = "chenxing:auth:login-ticket:";

#[derive(Clone)]
pub struct LoginTicketStore {
    client: Client,
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
    pub fn new(client: Client) -> Self {
        Self {
            client,
            metadata: None,
        }
    }

    pub fn new_with_pool(client: Client, metadata: crate::sqlx::PgPool) -> Self {
        Self {
            client,
            metadata: Some(metadata),
        }
    }

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

    pub async fn find(
        &self,
        ticket_id: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        self.read(ticket_id, false).await
    }

    pub async fn take(
        &self,
        ticket_id: &str,
    ) -> Result<Option<LoginTicket>, LoginTicketStoreError> {
        self.read(ticket_id, true).await
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
        let ticket = payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)?;
        let Some(ticket) = ticket else {
            return Ok(None);
        };
        if let Some(pool) = &self.metadata {
            let current_epoch: Option<i64> = crate::sqlx::query_scalar(
                "SELECT session_epoch FROM users WHERE id = $1",
            )
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
}
