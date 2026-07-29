use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Client};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::domain::Session;
use crate::users::domain::UserId;

#[derive(Clone)]
pub struct SessionStore {
    client: Client,
    key_prefix: String,
    metadata: Option<crate::sqlx::PgPool>,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("session metadata is unavailable")]
    MetadataUnavailable,
    #[error("session user id is invalid")]
    InvalidUserId,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl SessionStore {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
        }
    }

    pub fn with_metadata(client: Client, metadata: crate::sqlx::PgPool) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: Some(metadata),
        }
    }

    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
        serde_json::to_string(session)?;
        let metadata_id = if let Some(pool) = &self.metadata {
            let user_id = session
                .user_id
                .parse::<UserId>()
                .map_err(|_| SessionStoreError::InvalidUserId)?;
            let token_hash = Sha256::digest(session.token.as_bytes()).to_vec();
            let id = crate::sqlx::query_scalar(
                "INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at)
                 VALUES ($1, $2, $3, $4) RETURNING id",
            )
            .bind(&token_hash)
            .bind(user_id)
            .bind(session.created_at)
            .bind(session.expires_at)
            .fetch_one(pool)
            .await?;
            session.id = id;
            Some(id)
        } else {
            None
        };
        let payload = match serde_json::to_string(session) {
            Ok(payload) => payload,
            Err(error) => {
                self.delete_metadata(metadata_id).await;
                return Err(error.into());
            }
        };
        let mut connection = match self.client.get_multiplexed_async_connection().await {
            Ok(connection) => connection,
            Err(error) => {
                self.delete_metadata(metadata_id).await;
                return Err(error.into());
            }
        };
        if let Err(error) = connection
            .set_ex::<_, _, ()>(self.key(&session.token), payload, ttl.as_secs().max(1))
            .await
        {
            self.delete_metadata(metadata_id).await;
            return Err(error.into());
        }
        Ok(())
    }

    async fn delete_metadata(&self, id: Option<i64>) {
        if let (Some(pool), Some(id)) = (&self.metadata, id) {
            let _ = crate::sqlx::query("DELETE FROM user_sessions WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }
    }

    pub async fn find(&self, token: &str) -> Result<Option<Session>, SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(token)).await?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let mut session: Session = serde_json::from_str(&payload)?;
        if let Some(pool) = &self.metadata {
            let token_hash = Sha256::digest(token.as_bytes()).to_vec();
            let metadata: Option<(i64, UserId, time::OffsetDateTime, time::OffsetDateTime)> =
                crate::sqlx::query_as(
                    "SELECT id, user_id, created_at, expires_at FROM user_sessions
                 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()",
                )
                .bind(token_hash)
                .fetch_optional(pool)
                .await?;
            let Some((id, user_id, created_at, expires_at)) = metadata else {
                return Ok(None);
            };
            session.id = id;
            session.user_id = user_id.to_string();
            session.created_at = created_at;
            session.expires_at = expires_at;
        }
        let marker: Option<String> = connection
            .get(self.revocation_key(&session.user_id))
            .await?;
        if marker
            .and_then(|value| value.parse::<i128>().ok())
            .is_some_and(|before| session.created_at.unix_timestamp_nanos() <= before)
        {
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn revoke(&self, token: &str) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(self.key(token)).await?;
        if let Some(pool) = &self.metadata {
            let hash = Sha256::digest(token.as_bytes()).to_vec();
            crate::sqlx::query("UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE token_hash = $1")
                .bind(hash).execute(pool).await?;
        }
        Ok(())
    }

    pub async fn list_for_user(
        &self,
        user_id: UserId,
    ) -> Result<Vec<SessionSummary>, SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let rows = crate::sqlx::query_as::<_, (i64, time::OffsetDateTime, time::OffsetDateTime)>(
            "SELECT id, created_at, expires_at FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC")
            .bind(user_id).fetch_all(pool).await?;
        Ok(rows
            .into_iter()
            .map(|(id, created_at, expires_at)| SessionSummary {
                id,
                created_at,
                expires_at,
            })
            .collect())
    }

    pub async fn revoke_for_user(
        &self,
        user_id: UserId,
        session_id: i64,
    ) -> Result<bool, SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let found: Option<(Vec<u8>,)> = crate::sqlx::query_as("SELECT token_hash FROM user_sessions WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()")
            .bind(session_id).bind(user_id).fetch_optional(pool).await?;
        let Some((hash,)) = found else {
            return Ok(false);
        };
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(self.key_hash(&hash)).await?;
        crate::sqlx::query(
            "UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1",
        )
        .bind(session_id)
        .execute(pool)
        .await?;
        Ok(true)
    }

    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<(), SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let hashes: Vec<(Vec<u8>,)> = crate::sqlx::query_as("SELECT token_hash FROM user_sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()")
            .bind(user_id).fetch_all(pool).await?;
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let keys = hashes
            .iter()
            .map(|(hash,)| self.key_hash(hash))
            .collect::<Vec<_>>();
        if !keys.is_empty() {
            let _: usize = connection.del(keys).await?;
        }
        let before = time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string();
        let _: () = connection
            .set(self.revocation_key(&user_id.to_string()), before)
            .await?;
        crate::sqlx::query("UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE user_id = $1 AND revoked_at IS NULL").bind(user_id).execute(pool).await?;
        Ok(())
    }

    fn key(&self, token: &str) -> String {
        self.key_hash(&Sha256::digest(token.as_bytes()))
    }
    fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }
    fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: i64,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}
