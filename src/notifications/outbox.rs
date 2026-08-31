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
const VERIFICATION_CODE_KIND: &str = "verification_code";
const SECURITY_ALERT_KIND: &str = "email_change_security_alert";
const DELIVERY_SEMANTICS: &str = "at_least_once";

/// Durable email delivery intentionally uses **at-least-once** semantics.
///
/// The SMTP provider call happens before the PostgreSQL terminal-state update.
/// If that update or the transaction commit fails after SMTP accepted the
/// message, the row stays retryable and a later worker pass may send the same
/// message again. This favors eventual delivery of security-critical mail over
/// risking a permanently lost message when the commit result is ambiguous.
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
    #[error("email outbox payload is invalid")]
    InvalidPayload,
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
            Self::InvalidPayload => "invalid_payload",
        }
    }
}

struct OutboxEntry {
    id: i64,
    user_id: UserId,
    challenge_id: Uuid,
    kind: String,
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
        let row: Option<(i64, UserId, Uuid, String, i32, i64, String)> = crate::sqlx::query_as(
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
             RETURNING outbox.id, outbox.user_id, outbox.challenge_id, outbox.kind,
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
            |(id, user_id, challenge_id, kind, attempts, claim_generation, claim_token)| {
                OutboxEntry {
                    id,
                    user_id,
                    challenge_id,
                    kind,
                    attempts,
                    claim_generation,
                    claim_token,
                }
            },
        ))
    }

    async fn apply(&self, entry: &OutboxEntry) -> Result<bool, EmailOutboxError> {
        // Keep the user advisory lock until the provider call and terminal
        // write finish. A new challenge cannot commit between this state check
        // and delivery, so a claimed old challenge is either cancelled before
        // sending or is fully serialized ahead of the new request.
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, entry.user_id)
            .await
            .map_err(EmailOutboxError::Database)?;
        let message = self.load_message(&mut transaction, entry).await?;
        let Some(message) = message else {
            self.mark_cancelled(&mut transaction, entry).await?;
            transaction
                .commit()
                .await
                .map_err(EmailOutboxError::Database)?;
            return Ok(false);
        };
        tokio::time::timeout(EMAIL_SEND_TIMEOUT, self.sender.send(message))
            .await
            .map_err(|_| EmailOutboxError::DeliveryTimeout)?
            .map_err(|_| EmailOutboxError::Delivery)?;
        let processed = match self.mark_processed(&mut transaction, entry).await {
            Ok(processed) => processed,
            Err(error_value) => {
                self.log_delivery_state_uncertain(entry, "mark_processed", &error_value);
                return Err(error_value);
            }
        };
        if let Err(error_value) = transaction
            .commit()
            .await
            .map_err(EmailOutboxError::Database)
        {
            self.log_delivery_state_uncertain(entry, "commit", &error_value);
            return Err(error_value);
        }
        Ok(processed)
    }

    fn log_delivery_state_uncertain(
        &self,
        entry: &OutboxEntry,
        stage: &'static str,
        error_value: &EmailOutboxError,
    ) {
        tracing::error!(
            event = "email_outbox.delivery_state_uncertain",
            delivery_semantics = DELIVERY_SEMANTICS,
            outbox_id = entry.id,
            kind = %entry.kind,
            attempt = entry.attempts,
            stage,
            error_kind = error_value.failure_code(),
            "SMTP accepted an email but the durable terminal state could not be confirmed; retry may duplicate delivery"
        );
    }

    async fn load_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        match entry.kind.as_str() {
            VERIFICATION_CODE_KIND => self.load_verification_message(transaction, entry).await,
            SECURITY_ALERT_KIND => self.load_security_alert_message(transaction, entry).await,
            _ => Err(EmailOutboxError::InvalidPayload),
        }
    }

    async fn load_verification_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let row: Option<(String, Option<Vec<u8>>)> = crate::sqlx::query_as(
            "SELECT challenge.new_email, outbox.encrypted_code
             FROM email_outbox AS outbox
             JOIN user_email_change_challenges AS challenge
               ON challenge.id = outbox.challenge_id
             JOIN users ON users.id = outbox.user_id
             WHERE outbox.id = $1
               AND outbox.user_id = $2
               AND outbox.challenge_id = $3
               AND outbox.kind = $6
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
        .bind(VERIFICATION_CODE_KIND)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        let Some((recipient, encrypted_code)) = row else {
            return Ok(None);
        };
        let encrypted_code = encrypted_code.ok_or(EmailOutboxError::InvalidPayload)?;
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
        Ok(Some(EmailMessage {
            to: recipient,
            subject: "辰星通行证邮箱变更验证码".to_owned(),
            body: format!(
                "你的邮箱变更验证码是：{}\n验证码将在 10 分钟后失效。",
                code.as_str()
            ),
        }))
    }

    async fn load_security_alert_message(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let recipient: Option<String> = crate::sqlx::query_scalar(
            "SELECT outbox.recipient
             FROM email_outbox AS outbox
             JOIN user_email_change_challenges AS challenge
               ON challenge.id = outbox.challenge_id
             WHERE outbox.id = $1
               AND outbox.user_id = $2
               AND outbox.challenge_id = $3
               AND outbox.kind = $4
               AND outbox.processed_at IS NULL
               AND outbox.cancelled_at IS NULL
               AND outbox.dead_lettered_at IS NULL
               AND outbox.claim_generation = $5
               AND outbox.claim_token = $6
               AND challenge.consumed_at IS NOT NULL
              FOR UPDATE OF outbox",
        )
        .bind(entry.id)
        .bind(entry.user_id)
        .bind(entry.challenge_id)
        .bind(SECURITY_ALERT_KIND)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(EmailOutboxError::Database)?;
        let Some(recipient) = recipient else {
            return Ok(None);
        };
        let recipient = crate::users::email::EmailAddress::parse(&recipient)
            .map_err(|_| EmailOutboxError::InvalidRecipient)?;
        Ok(Some(EmailMessage {
            to: recipient,
            subject: "辰星通行证邮箱已变更".to_owned(),
            body: "你的账户邮箱已变更。如果这不是你的操作，请立即联系管理员。".to_owned(),
        }))
    }

    async fn mark_processed(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        entry: &OutboxEntry,
    ) -> Result<bool, EmailOutboxError> {
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
        .execute(&mut **transaction)
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
