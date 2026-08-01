use std::time::Duration;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use redis::{AsyncCommands, Client};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use super::domain::Session;
use crate::users::domain::UserId;

const PAYLOAD_NONCE_LENGTH: usize = 12;

type SessionMetadataRow = (i64, UserId, OffsetDateTime, OffsetDateTime, Option<Vec<u8>>);
#[derive(Clone)]
pub struct SessionStore {
    pub(super) client: Client,
    pub(super) key_prefix: String,
    pub(super) metadata: Option<crate::sqlx::PgPool>,
    pub(super) encryption_key: Option<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("redis operation failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("session serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("session payload encryption failed")]
    PayloadEncryption,
    #[error("session payload decryption failed")]
    PayloadDecryption,
    #[error("session payload encoding failed")]
    PayloadEncoding,
    #[error("session metadata is unavailable")]
    MetadataUnavailable,
    #[error("session outbox record is invalid")]
    InvalidOutbox,
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
            encryption_key: None,
        }
    }

    pub fn with_metadata_and_key(
        client: Client,
        metadata: crate::sqlx::PgPool,
        encryption_key: [u8; 32],
    ) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: Some(metadata),
            encryption_key: Some(encryption_key),
        }
    }

    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
        if self.metadata.is_none() {
            let payload = serde_json::to_string(session)?;
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            connection
                .set_ex::<_, _, ()>(self.key(&session.token), payload, ttl.as_secs().max(1))
                .await?;
            return Ok(());
        }

        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let user_id = session
            .user_id
            .parse::<UserId>()
            .map_err(|_| SessionStoreError::InvalidUserId)?;
        let token_hash = Sha256::digest(session.token.as_bytes()).to_vec();
        let mut transaction = pool.begin().await?;
        let id: i64 = crate::sqlx::query_scalar(
            "INSERT INTO user_sessions
                 (token_hash, user_id, created_at, expires_at, session_payload)
             VALUES ($1, $2, $3, $4, NULL)
             RETURNING id",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(session.created_at)
        .bind(session.expires_at)
        .fetch_one(&mut *transaction)
        .await?;
        session.id = id;
        let encrypted_payload = self.encrypt_payload(&serde_json::to_vec(session)?)?;
        crate::sqlx::query("UPDATE user_sessions SET session_payload = $1 WHERE id = $2")
            .bind(encrypted_payload)
            .bind(id)
            .execute(&mut *transaction)
            .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox
                 (operation, session_id, user_id, token_hash)
             VALUES ('sync_session', $1, $2, $3)",
        )
        .bind(id)
        .bind(user_id)
        .bind(&token_hash)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn find(&self, token: &str) -> Result<Option<Session>, SessionStoreError> {
        if let Some(pool) = &self.metadata {
            let token_hash = Sha256::digest(token.as_bytes()).to_vec();
            let metadata: Option<SessionMetadataRow> = crate::sqlx::query_as(
                "SELECT id, user_id, created_at, expires_at, session_payload
                 FROM user_sessions
                 WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > NOW()",
            )
            .bind(&token_hash)
            .fetch_optional(pool)
            .await?;
            let Some((id, user_id, created_at, expires_at, payload)) = metadata else {
                return Ok(None);
            };
            let mut session: Session = if let Some(payload) = payload {
                serde_json::from_slice(&self.decrypt_payload(&payload)?)?
            } else {
                let mut connection = self.client.get_multiplexed_async_connection().await?;
                let Some(payload): Option<String> = connection.get(self.key(token)).await? else {
                    return Ok(None);
                };
                serde_json::from_str(&payload)?
            };
            session.id = id;
            session.token = token.to_owned();
            session.user_id = user_id.to_string();
            session.created_at = created_at;
            session.expires_at = expires_at;
            session.revoked_at = None;
            return Ok(Some(session));
        }

        let mut connection = self.client.get_multiplexed_async_connection().await?;
        let payload: Option<String> = connection.get(self.key(token)).await?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let session: Session = serde_json::from_str(&payload)?;
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
        let hash = Sha256::digest(token.as_bytes()).to_vec();
        let Some(pool) = &self.metadata else {
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            let _: usize = connection.del(self.key_hash(&hash)).await?;
            return Ok(());
        };
        let mut transaction = pool.begin().await?;
        crate::sqlx::query(
            "UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE token_hash = $1",
        )
        .bind(&hash)
        .execute(&mut *transaction)
        .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox (operation, token_hash)
             VALUES ('revoke_session', $1)",
        )
        .bind(&hash)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
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
        let rows = crate::sqlx::query_as::<_, (i64, OffsetDateTime, OffsetDateTime)>(
            "SELECT id, created_at, expires_at
             FROM user_sessions
             WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()
             ORDER BY created_at DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
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
        let mut transaction = pool.begin().await?;
        let found: Option<(Vec<u8>,)> = crate::sqlx::query_as(
            "SELECT token_hash
             FROM user_sessions
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW()
             FOR UPDATE",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((hash,)) = found else {
            transaction.rollback().await?;
            return Ok(false);
        };
        crate::sqlx::query("UPDATE user_sessions SET revoked_at = NOW() WHERE id = $1")
            .bind(session_id)
            .execute(&mut *transaction)
            .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox (operation, session_id, user_id, token_hash)
             VALUES ('revoke_session', $1, $2, $3)",
        )
        .bind(session_id)
        .bind(user_id)
        .bind(&hash)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn revoke_all_for_user(&self, user_id: UserId) -> Result<(), SessionStoreError> {
        let pool = self
            .metadata
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let revoked_before = OffsetDateTime::now_utc();
        let mut transaction = pool.begin().await?;
        crate::sqlx::query(
            "UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, $2)
             WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(revoked_before)
        .execute(&mut *transaction)
        .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox (operation, session_id, user_id, token_hash)
             SELECT 'revoke_session', id, user_id, token_hash
             FROM user_sessions
             WHERE user_id = $1 AND revoked_at = $2",
        )
        .bind(user_id)
        .bind(revoked_before)
        .execute(&mut *transaction)
        .await?;
        crate::sqlx::query(
            "INSERT INTO session_outbox (operation, user_id, created_at)
             VALUES ('revoke_user', $1, $2)",
        )
        .bind(user_id)
        .bind(revoked_before)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| SessionStoreError::PayloadEncryption)?;
        let mut nonce_bytes = [0_u8; PAYLOAD_NONCE_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), payload)
            .map_err(|_| SessionStoreError::PayloadEncryption)?;
        let mut encrypted = nonce_bytes.to_vec();
        encrypted.extend(ciphertext);
        Ok(encrypted)
    }

    pub(super) fn decrypt_payload(&self, encrypted: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        if encrypted.len() <= PAYLOAD_NONCE_LENGTH {
            return Err(SessionStoreError::PayloadDecryption);
        }
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| SessionStoreError::PayloadDecryption)?;
        cipher
            .decrypt(
                Nonce::from_slice(&encrypted[..PAYLOAD_NONCE_LENGTH]),
                &encrypted[PAYLOAD_NONCE_LENGTH..],
            )
            .map_err(|_| SessionStoreError::PayloadDecryption)
    }

    fn key(&self, token: &str) -> String {
        self.key_hash(&Sha256::digest(token.as_bytes()))
    }

    pub(super) fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }

    pub(super) fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}
