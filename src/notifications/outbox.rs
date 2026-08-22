use std::{sync::Arc, time::Duration};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    config::AuthEncryptionKeyRing,
    notifications::{EmailMessage, EmailSender, crypto::decrypt_code},
    sqlx::{PgPool, Postgres, Transaction},
    users::domain::UserId,
    workers::WorkerContext,
};

#[path = "outbox_retention.rs"]
mod retention;
#[path = "outbox_retry.rs"]
mod retry;

const OUTBOX_LEASE: time::Duration = time::Duration::minutes(5);
const MAX_ATTEMPTS: i32 = 10;
const EMAIL_SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct EmailOutbox {
    pool: PgPool,
    encryption_keys: AuthEncryptionKeyRing,
    sender: Arc<dyn EmailSender>,
}

#[derive(Debug, thiserror::Error)]
pub enum EmailOutboxError {
    #[error("email outbox database operation failed")]
    Database(#[source] crate::sqlx::Error),
    #[error("email outbox delivery failed")]
    Delivery,
    #[error("email outbox delivery timed out")]
    DeliveryTimeout,
    #[error("email outbox code decryption failed")]
    Decryption,
    #[error("email outbox code is invalid")]
    InvalidCode,
    #[error("email outbox recipient is invalid")]
    InvalidRecipient,
}

impl EmailOutboxError {
    fn failure_code(&self) -> &'static str {
        match self {
            Self::Database(_) => "database_failure",
            Self::Delivery => "delivery_failure",
            Self::DeliveryTimeout => "delivery_timeout",
            Self::Decryption => "code_decryption_failure",
            Self::InvalidCode => "invalid_code",
            Self::InvalidRecipient => "invalid_recipient",
        }
    }
}

struct OutboxEntry {
    id: i64,
    user_id: UserId,
    challenge_id: Uuid,
    attempts: i32,
    claim_generation: i64,
    claim_token: String,
}

impl EmailOutbox {
    pub(crate) fn new(
        pool: PgPool,
        encryption_keys: AuthEncryptionKeyRing,
        sender: Arc<dyn EmailSender>,
    ) -> Self {
        Self {
            pool,
            encryption_keys,
            sender,
        }
    }

    pub(crate) fn with_sender(mut self, sender: Arc<dyn EmailSender>) -> Self {
        self.sender = sender;
        self
    }

    pub async fn process_pending_outbox(&self) -> Result<usize, EmailOutboxError> {
        let mut processed = 0;
        while let Some(entry) = self.claim().await? {
            match self.apply(&entry).await {
                Ok(true) => processed += 1,
                Ok(false) => {}
                Err(error_value) => self.record_failure(&entry, &error_value).await?,
            }
        }
        Ok(processed)
    }

    pub async fn run_worker(self, mut worker: WorkerContext) {
        let mut next_cleanup = tokio::time::Instant::now();
        loop {
            worker.reporter().heartbeat();
            let mut failed = false;
            if let Err(error_value) = self.process_pending_outbox().await {
                failed = true;
                tracing::error!(
                    error_kind = error_value.failure_code(),
                    "email outbox worker failed"
                );
            }
            if tokio::time::Instant::now() >= next_cleanup {
                if let Err(error_value) = self.prune_settled_outbox().await {
                    failed = true;
                    tracing::error!(
                        error_kind = error_value.failure_code(),
                        "email outbox retention failed"
                    );
                }
                next_cleanup = tokio::time::Instant::now() + Duration::from_secs(300);
            }
            if failed {
                worker.reporter().retryable_failure();
            } else {
                worker.reporter().success();
            }
            if worker.sleep_or_shutdown(Duration::from_secs(1)).await {
                break;
            }
        }
    }

    async fn claim(&self) -> Result<Option<OutboxEntry>, EmailOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        let claim_token = Uuid::new_v4().simple().to_string();
        let row: Option<(i64, UserId, Uuid, i32, i64, String)> = crate::sqlx::query_as(
            "WITH next AS (
                 SELECT id FROM email_outbox
                 WHERE processed_at IS NULL
                   AND cancelled_at IS NULL
                   AND dead_lettered_at IS NULL
                   AND available_at <= NOW()
                 ORDER BY id
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             UPDATE email_outbox AS outbox
             SET attempts = LEAST(outbox.attempts, 2147483646) + 1,
                 claim_generation = outbox.claim_generation + 1,
                 claim_token = $2,
                 available_at = NOW() + $1
             FROM next
             WHERE outbox.id = next.id
             RETURNING outbox.id, outbox.user_id, outbox.challenge_id,
                       outbox.attempts, outbox.claim_generation, outbox.claim_token",
        )
        .bind(OUTBOX_LEASE)
        .bind(&claim_token)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        transaction
            .commit()
            .await
            .map_err(EmailOutboxError::Database)?;
        Ok(row.map(
            |(id, user_id, challenge_id, attempts, claim_generation, claim_token)| OutboxEntry {
                id,
                user_id,
                challenge_id,
                attempts,
                claim_generation,
                claim_token,
            },
        ))
    }

    async fn apply(&self, entry: &OutboxEntry) -> Result<bool, EmailOutboxError> {
        // The provider call stays outside the database transaction. The claim
        // generation/token fence makes completion safe after a lease is reclaimed;
        // without a provider idempotency key, delivery is intentionally at-least-once.
        let payload = self.load_current_payload(entry).await?;
        let Some((recipient, encrypted_code)) = payload else {
            self.mark_cancelled(entry).await?;
            return Ok(false);
        };
        let code = decrypt_code(
            &self.encryption_keys,
            encrypted_code.as_slice(),
            entry.user_id,
            entry.challenge_id,
        )
        .map_err(|_| EmailOutboxError::Decryption)?;
        if code.len() != 6 || !code.iter().all(u8::is_ascii_digit) {
            return Err(EmailOutboxError::InvalidCode);
        }
        let code = Zeroizing::new(
            String::from_utf8(code.to_vec()).map_err(|_| EmailOutboxError::InvalidCode)?,
        );
        let recipient = crate::users::email::EmailAddress::parse(&recipient)
            .map_err(|_| EmailOutboxError::InvalidRecipient)?;
        let message = EmailMessage {
            to: recipient,
            subject: "辰星通行证邮箱变更验证码".to_owned(),
            body: format!(
                "你的邮箱变更验证码是：{}\n验证码将在 10 分钟后失效。",
                code.as_str()
            ),
        };
        tokio::time::timeout(EMAIL_SEND_TIMEOUT, self.sender.send(message))
            .await
            .map_err(|_| EmailOutboxError::DeliveryTimeout)?
            .map_err(|_| EmailOutboxError::Delivery)?;
        self.mark_processed(entry).await
    }

    async fn load_current_payload(
        &self,
        entry: &OutboxEntry,
    ) -> Result<Option<(String, Zeroizing<Vec<u8>>)>, EmailOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, entry.user_id)
            .await
            .map_err(EmailOutboxError::Database)?;
        let row: Option<(String, Vec<u8>)> = crate::sqlx::query_as(
            "SELECT challenge.new_email, outbox.encrypted_code
             FROM email_outbox AS outbox
             JOIN user_email_change_challenges AS challenge
               ON challenge.id = outbox.challenge_id
             JOIN users ON users.id = outbox.user_id
             WHERE outbox.id = $1
               AND outbox.user_id = $2
               AND outbox.challenge_id = $3
               AND outbox.processed_at IS NULL
               AND outbox.cancelled_at IS NULL
               AND outbox.dead_lettered_at IS NULL
               AND outbox.claim_generation = $4
               AND outbox.claim_token = $5
               AND challenge.consumed_at IS NULL
               AND challenge.expires_at > NOW()
               AND challenge.security_epoch = users.session_epoch
               AND users.status = 'active'
             FOR UPDATE OF outbox",
        )
        .bind(entry.id)
        .bind(entry.user_id)
        .bind(entry.challenge_id)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        if row.is_none() {
            self.mark_cancelled(&mut transaction, entry).await?;
        }
        transaction
            .commit()
            .await
            .map_err(EmailOutboxError::Database)?;
        Ok(row.map(|(recipient, encrypted_code)| (recipient, Zeroizing::new(encrypted_code))))
    }

    async fn mark_processed(&self, entry: &OutboxEntry) -> Result<bool, EmailOutboxError> {
        let result = crate::sqlx::query(
            "UPDATE email_outbox
             SET processed_at = NOW(), claim_token = '', last_error = NULL
             WHERE id = $1 AND processed_at IS NULL AND cancelled_at IS NULL
               AND dead_lettered_at IS NULL
               AND claim_generation = $2 AND claim_token = $3",
        )
        .bind(entry.id)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .execute(&self.pool)
        .await
        .map_err(EmailOutboxError::Database)?;
        Ok(result.rows_affected() == 1)
    }

    async fn mark_cancelled(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<(), EmailOutboxError> {
        crate::sqlx::query(
            "UPDATE email_outbox
             SET cancelled_at = NOW(), claim_token = '', last_error = NULL
             WHERE id = $1 AND processed_at IS NULL AND cancelled_at IS NULL
               AND dead_lettered_at IS NULL
               AND claim_generation = $2 AND claim_token = $3",
        )
        .bind(entry.id)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .execute(&mut **transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        Ok(())
    }
}
