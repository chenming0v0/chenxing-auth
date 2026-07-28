use std::time::Duration;

use redis::{AsyncCommands, Client};
use thiserror::Error;
use uuid::Uuid;

use super::domain::Session;

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

    pub async fn save(&self, session: &Session, ttl: Duration) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload = serde_json::to_string(session)?;
        let _: () = connection
            .set_ex(self.key(&session.id), payload, ttl.as_secs().max(1))
            .await?;
        if let Some(pool) = &self.metadata {
            let user_id = uuid::Uuid::parse_str(&session.user_id)
                .map_err(|_| SessionStoreError::InvalidUserId)?;
            crate::sqlx::query(
                "INSERT INTO user_sessions (id, user_id, created_at, expires_at, revoked_at)
                 VALUES ($1, $2, $3, $4, NULL)
                 ON CONFLICT (id) DO UPDATE SET expires_at = EXCLUDED.expires_at, revoked_at = NULL",
            )
            .bind(session.id)
            .bind(user_id)
            .bind(session.created_at)
            .bind(session.expires_at)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    pub async fn find(&self, id: Uuid) -> Result<Option<Session>, SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(&id)).await?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let session: Session = serde_json::from_str(&payload)?;
        let marker: Option<String> = connection
            .get(self.revocation_key(&session.user_id))
            .await?;
        if marker
            .and_then(|value| value.parse::<i128>().ok())
            .is_some_and(|revoked_before| {
                session.created_at.unix_timestamp_nanos() <= revoked_before
            })
        {
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn revoke(&self, id: Uuid) -> Result<(), SessionStoreError> {
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: usize = connection.del(self.key(&id)).await?;
        if let Some(pool) = &self.metadata {
            crate::sqlx::query(
                "UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, NOW()) WHERE id = $1",
            )
            .bind(id)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    pub async fn list_for_user(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<Vec<SessionSummary>, SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let rows = crate::sqlx::query_as::<_, (Uuid, time::OffsetDateTime, time::OffsetDateTime)>(
            "SELECT id, created_at, expires_at FROM user_sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        let mut active = Vec::with_capacity(rows.len());
        for (id, created_at, expires_at) in rows {
            if self
                .find(id)
                .await?
                .is_some_and(|session| session.is_active())
            {
                active.push(SessionSummary {
                    id,
                    created_at,
                    expires_at,
                });
            }
        }
        Ok(active)
    }

    pub async fn revoke_for_user(
        &self,
        user_id: uuid::Uuid,
        session_id: uuid::Uuid,
    ) -> Result<bool, SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let found: Option<(Uuid,)> = crate::sqlx::query_as(
            "SELECT id FROM user_sessions
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
        if found.is_none() {
            return Ok(false);
        }
        self.revoke(session_id).await?;
        Ok(true)
    }

    pub async fn revoke_all_for_user(&self, user_id: uuid::Uuid) -> Result<(), SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let session_ids: Vec<(Uuid,)> = crate::sqlx::query_as(
            "SELECT id FROM user_sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        let revoked_before = time::OffsetDateTime::now_utc()
            .unix_timestamp_nanos()
            .to_string();
        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let _: () = connection
            .set(self.revocation_key(&user_id.to_string()), revoked_before)
            .await?;
        let keys = session_ids
            .iter()
            .map(|(id,)| self.key(id))
            .collect::<Vec<_>>();
        if !keys.is_empty() {
            let _: usize = connection.del(keys).await?;
        }
        crate::sqlx::query(
            "UPDATE user_sessions SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    fn key(&self, id: &Uuid) -> String {
        format!("{}{id}", self.key_prefix)
    }

    fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: Uuid,
    pub created_at: time::OffsetDateTime,
    pub expires_at: time::OffsetDateTime,
}
