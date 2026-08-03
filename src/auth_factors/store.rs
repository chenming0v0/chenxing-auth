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
}

#[derive(Debug, Error)]
pub enum LoginTicketStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("login ticket serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl LoginTicketStore {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    pub async fn create(
        &self,
        user_id: UserId,
        methods: Vec<FactorMethod>,
    ) -> Result<(String, LoginTicket), LoginTicketStoreError> {
        let ticket_id = Uuid::new_v4().to_string();
        let ticket = LoginTicket::new(user_id, methods);
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
        payload
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(LoginTicketStoreError::from)
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
