use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use redis::{AsyncCommands, Client, Script};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use super::{crypto, domain::Session};
use crate::{
    config::AuthEncryptionKeyRing,
    sqlx::{Postgres, Transaction},
    users::domain::UserId,
};

const REDIS_ONLY_SESSION_SET: &str = "local marker = redis.call('GET', KEYS[1])\nif marker and tonumber(marker) >= tonumber(ARGV[1]) then return 0 end\nredis.call('SET', KEYS[2], ARGV[2], 'EX', ARGV[3])\nreturn 1";
const REDIS_ONLY_ADVANCE_WATERMARK: &str = "local current = redis.call('GET', KEYS[1])\nif not current or tonumber(current) < tonumber(ARGV[1]) then redis.call('SET', KEYS[1], ARGV[1]) end\nreturn 1";

type SessionMetadataRow = (i64, UserId, OffsetDateTime, OffsetDateTime, Option<Vec<u8>>);
#[derive(Clone)]
pub struct SessionStore {
    pub(super) client: Client,
    pub(super) key_prefix: String,
    pub(super) metadata: Option<crate::sqlx::PgPool>,
    pub(super) encryption_keys: Option<AuthEncryptionKeyRing>,
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
    #[error("session user is not active")]
    UserDisabled,
    #[error("session user was not found")]
    UserNotFound,
    #[error("session was rejected by a revocation watermark")]
    SessionRevoked,
    #[error("database operation failed: {0}")]
    Database(#[from] crate::sqlx::Error),
}

impl SessionStore {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: None,
        }
    }

    pub fn with_redis_key(client: Client, encryption_key: [u8; 32]) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: None,
            encryption_keys: Some(AuthEncryptionKeyRing::single(
                crate::config::AuthEncryptionKey::new(encryption_key),
            )),
        }
    }

    pub fn with_metadata_and_key(
        client: Client,
        metadata: crate::sqlx::PgPool,
        encryption_key: [u8; 32],
    ) -> Self {
        Self::with_metadata_and_key_ring(
            client,
            metadata,
            AuthEncryptionKeyRing::single(crate::config::AuthEncryptionKey::new(encryption_key)),
        )
    }

    pub fn with_metadata_and_key_ring(
        client: Client,
        metadata: crate::sqlx::PgPool,
        encryption_keys: AuthEncryptionKeyRing,
    ) -> Self {
        Self {
            client,
            key_prefix: "chenxing:session:".to_owned(),
            metadata: Some(metadata),
            encryption_keys: Some(encryption_keys),
        }
    }

    pub async fn save(
        &self,
        session: &mut Session,
        ttl: Duration,
    ) -> Result<(), SessionStoreError> {
        if self.metadata.is_none() {
            let payload = crypto::encrypt(
                self.encryption_keys
                    .as_ref()
                    .ok_or(SessionStoreError::MetadataUnavailable)?,
                &serde_json::to_vec(session)?,
            )?;
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            let created_at = timestamp_watermark(session.created_at);
            let stored: i64 = Script::new(REDIS_ONLY_SESSION_SET)
                .key(self.redis_only_revocation_key(&session.user_id))
                .key(self.key(&session.token))
                .arg(created_at)
                .arg(payload)
                .arg(ttl.as_secs().max(1))
                .invoke_async(&mut connection)
                .await?;
            if stored == 0 {
                return Err(SessionStoreError::SessionRevoked);
            }
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
        lock_user_session_scope(&mut transaction, user_id).await?;
        let user_state: Option<(i64, String)> = crate::sqlx::query_as(
            "SELECT session_epoch, status FROM users WHERE id = $1 FOR UPDATE",
        )
        .bind(user_id)
        .fetch_optional(&mut *transaction)
        .await?;
        let Some((session_epoch, status)) = user_state else {
            return Err(SessionStoreError::UserNotFound);
        };
        if status != "active" {
            return Err(SessionStoreError::UserDisabled);
        }
        let id: i64 = crate::sqlx::query_scalar(
            "INSERT INTO user_sessions
                 (token_hash, user_id, created_at, expires_at, session_payload, session_epoch)
             VALUES ($1, $2, $3, $4, NULL, $5)
             RETURNING id",
        )
        .bind(&token_hash)
        .bind(user_id)
        .bind(session.created_at)
        .bind(session.expires_at)
        .bind(session_epoch)
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
                 (operation, session_id, user_id, token_hash, generation)
             VALUES ('sync_session', $1, $2, $3, $4)",
        )
        .bind(id)
        .bind(user_id)
        .bind(&token_hash)
        .bind(session_epoch)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn find(&self, token: &str) -> Result<Option<Session>, SessionStoreError> {
        if let Some(pool) = &self.metadata {
            let token_hash = Sha256::digest(token.as_bytes()).to_vec();
            let metadata: Option<SessionMetadataRow> = crate::sqlx::query_as(
                "SELECT sessions.id, sessions.user_id, sessions.created_at,
                        sessions.expires_at, sessions.session_payload
                 FROM user_sessions AS sessions
                 JOIN users ON users.id = sessions.user_id
                 WHERE sessions.token_hash = $1
                   AND sessions.revoked_at IS NULL
                   AND sessions.expires_at > NOW()
                   AND sessions.session_epoch >= users.session_epoch
                   AND users.status = 'active'",
            )
            .bind(&token_hash)
            .fetch_optional(pool)
            .await?;
            let Some((id, user_id, created_at, expires_at, payload)) = metadata else {
                return Ok(None);
            };
            let decoded_session: Option<Session> = if let Some(payload) = payload {
                crypto::decrypt(
                    self.encryption_keys
                        .as_ref()
                        .ok_or(SessionStoreError::MetadataUnavailable)?,
                    &payload,
                )
                .ok()
                .and_then(|payload| serde_json::from_slice(&payload).ok())
            } else {
                let mut connection = self.client.get_multiplexed_async_connection().await?;
                let Some(payload): Option<Vec<u8>> = connection.get(self.key(token)).await? else {
                    return Ok(None);
                };
                crypto::decrypt(
                    self.encryption_keys
                        .as_ref()
                        .ok_or(SessionStoreError::MetadataUnavailable)?,
                    &payload,
                )
                .ok()
                .and_then(|payload| serde_json::from_slice(&payload).ok())
            };
            let Some(mut session) = decoded_session else {
                return Ok(None);
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
        let payload: Option<Vec<u8>> = connection.get(self.key(token)).await?;
        let Some(payload) = payload else {
            return Ok(None);
        };
        let decoded_session: Option<Session> = crypto::decrypt(
            self.encryption_keys
                .as_ref()
                .ok_or(SessionStoreError::MetadataUnavailable)?,
            &payload,
        )
        .ok()
        .and_then(|payload| serde_json::from_slice(&payload).ok());
        let Some(session) = decoded_session else {
            return Ok(None);
        };
        let marker: Option<String> = connection
            .get(self.redis_only_revocation_key(&session.user_id))
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
            "SELECT sessions.id, sessions.created_at, sessions.expires_at
             FROM user_sessions AS sessions
             JOIN users ON users.id = sessions.user_id
             WHERE sessions.user_id = $1
               AND sessions.revoked_at IS NULL
               AND sessions.expires_at > NOW()
               AND sessions.session_epoch >= users.session_epoch
               AND users.status = 'active'
             ORDER BY sessions.created_at DESC",
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
        lock_user_session_scope(&mut transaction, user_id).await?;
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
            "INSERT INTO session_outbox
                 (operation, session_id, user_id, token_hash, generation)
             VALUES ('revoke_session', $1, $2, $3, 0)",
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
        let Some(pool) = self.metadata.as_ref() else {
            let mut connection = self.client.get_multiplexed_async_connection().await?;
            let _: i64 = Script::new(REDIS_ONLY_ADVANCE_WATERMARK)
                .key(self.redis_only_revocation_key(&user_id.to_string()))
                .arg(timestamp_watermark(OffsetDateTime::now_utc()))
                .invoke_async(&mut connection)
                .await?;
            return Ok(());
        };
        let mut transaction = pool.begin().await?;
        if revoke_all_for_user_in_transaction(&mut transaction, user_id)
            .await?
            .is_none()
        {
            return Err(SessionStoreError::UserNotFound);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub(super) fn encrypt_payload(&self, payload: &[u8]) -> Result<Vec<u8>, SessionStoreError> {
        let keys = self
            .encryption_keys
            .as_ref()
            .ok_or(SessionStoreError::MetadataUnavailable)?;
        crypto::encrypt(keys, payload)
    }

    fn key(&self, token: &str) -> String {
        self.key_hash(&Sha256::digest(token.as_bytes()))
    }

    pub(super) fn key_hash(&self, hash: &[u8]) -> String {
        format!("{}{}", self.key_prefix, URL_SAFE_NO_PAD.encode(hash))
    }

    pub(super) fn revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-epoch:{user_id}", self.key_prefix)
    }

    pub(super) fn redis_only_revocation_key(&self, user_id: &str) -> String {
        format!("{}revoked-before:{user_id}", self.key_prefix)
    }
}

fn timestamp_watermark(value: OffsetDateTime) -> i64 {
    value
        .unix_timestamp_nanos()
        .clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

pub(crate) async fn lock_user_session_scope(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<(), crate::sqlx::Error> {
    crate::sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(user_id)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) async fn revoke_all_for_user_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: UserId,
) -> Result<Option<i64>, crate::sqlx::Error> {
    lock_user_session_scope(transaction, user_id).await?;
    let epoch: Option<i64> = crate::sqlx::query_scalar(
        "UPDATE users
         SET session_epoch = session_epoch + 1, updated_at = NOW()
         WHERE id = $1
         RETURNING session_epoch",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(epoch) = epoch else {
        return Ok(None);
    };

    crate::sqlx::query(
        "WITH revoked AS (
             UPDATE user_sessions
             SET revoked_at = COALESCE(revoked_at, NOW())
             WHERE user_id = $1 AND revoked_at IS NULL
             RETURNING id, user_id, token_hash
         )
         INSERT INTO session_outbox
             (operation, session_id, user_id, token_hash, generation)
         SELECT 'revoke_session', id, user_id, token_hash, $2
         FROM revoked",
    )
    .bind(user_id)
    .bind(epoch)
    .execute(&mut **transaction)
    .await?;
    crate::sqlx::query(
        "INSERT INTO session_outbox (operation, user_id, generation)
         VALUES ('revoke_user', $1, $2)",
    )
    .bind(user_id)
    .bind(epoch)
    .execute(&mut **transaction)
    .await?;
    Ok(Some(epoch))
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: i64,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
}
