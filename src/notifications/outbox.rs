use std::{future::Future, sync::Arc, time::Duration};

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
const WORKER_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const WORKER_BATCH_TIME_BUDGET: Duration = Duration::from_secs(5);
const WORKER_BATCH_ENTRY_LIMIT: usize = 100;
const WORKER_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
const VERIFICATION_CODE_KIND: &str = "verification_code";
const SECURITY_ALERT_KIND: &str = "email_change_security_alert";

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
            if self.process_claimed_entry(&entry).await? {
                processed += 1;
            }
        }
        Ok(processed)
    }

    pub async fn run_worker(self, mut worker: WorkerContext) {
        let mut next_cleanup = tokio::time::Instant::now();
        let reporter = worker.reporter().clone();
        loop {
            reporter.heartbeat();
            let mut failed = false;
            let batch_result = heartbeat_while(
                self.process_worker_batch(),
                WORKER_HEARTBEAT_INTERVAL,
                || reporter.heartbeat(),
            )
            .await;
            if let Err(error_value) = batch_result {
                failed = true;
                tracing::error!(
                    error_kind = error_value.failure_code(),
                    "email outbox worker failed"
                );
            }
            if tokio::time::Instant::now() >= next_cleanup {
                let cleanup_result = heartbeat_while(
                    self.prune_settled_outbox(),
                    WORKER_HEARTBEAT_INTERVAL,
                    || reporter.heartbeat(),
                )
                .await;
                if let Err(error_value) = cleanup_result {
                    failed = true;
                    tracing::error!(
                        error_kind = error_value.failure_code(),
                        "email outbox retention failed"
                    );
                }
                next_cleanup = tokio::time::Instant::now() + WORKER_CLEANUP_INTERVAL;
            }
            if failed {
                reporter.retryable_failure();
            } else {
                // Success means a bounded pass completed without an infrastructure error. It
                // does not require the queue to be empty: sustained, healthy delivery remains
                // ready while queue depth is monitored separately.
                reporter.success();
            }
            if worker.sleep_or_shutdown(Duration::from_secs(1)).await {
                break;
            }
        }
    }

    async fn process_worker_batch(&self) -> Result<usize, EmailOutboxError> {
        let started = tokio::time::Instant::now();
        let mut handled = 0;
        let mut processed = 0;
        while worker_batch_has_capacity(handled, started.elapsed()) {
            let Some(entry) = self.claim().await? else {
                break;
            };
            handled += 1;
            if self.process_claimed_entry(&entry).await? {
                processed += 1;
            }
        }
        Ok(processed)
    }

    async fn process_claimed_entry(&self, entry: &OutboxEntry) -> Result<bool, EmailOutboxError> {
        match self.apply(entry).await {
            Ok(processed) => Ok(processed),
            Err(error_value) => {
                self.record_failure(entry, &error_value).await?;
                Ok(false)
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
        // Claim validation and payload reads use a short transaction. The
        // provider call must stay outside it: SMTP may wait for network I/O and
        // the claim fence makes the later terminal CAS safe if the lease is
        // reclaimed while delivery is in flight.
        let message = self.load_message(entry).await?;
        let Some(message) = message else {
            return Ok(false);
        };
        tokio::time::timeout(EMAIL_SEND_TIMEOUT, self.sender.send(message))
            .await
            .map_err(|_| EmailOutboxError::DeliveryTimeout)?
            .map_err(|_| EmailOutboxError::Delivery)?;
        // SMTP succeeds before this fenced write. If the write or its commit
        // is lost, retrying the durable row may duplicate delivery by design:
        // this boundary guarantees at-least-once delivery rather than loss.
        let processed = self.mark_processed(entry).await?;
        if !processed {
            tracing::warn!(
                outbox_id = entry.id,
                claim_generation = entry.claim_generation,
                kind = %entry.kind,
                event = "email_outbox.stale_claim",
                "stale email outbox completion ignored"
            );
        }
        Ok(processed)
    }

    async fn load_message(
        &self,
        entry: &OutboxEntry,
    ) -> Result<Option<EmailMessage>, EmailOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        crate::sessions::store::lock_user_session_scope(&mut transaction, entry.user_id)
            .await
            .map_err(EmailOutboxError::Database)?;
        let message = self
            .load_message_in_transaction(&mut transaction, entry)
            .await?;
        if message.is_none() {
            self.mark_cancelled(&mut transaction, entry).await?;
        }
        transaction
            .commit()
            .await
            .map_err(EmailOutboxError::Database)?;
        Ok(message)
    }

    async fn load_message_in_transaction(
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

fn worker_batch_has_capacity(handled: usize, elapsed: Duration) -> bool {
    handled < WORKER_BATCH_ENTRY_LIMIT && elapsed < WORKER_BATCH_TIME_BUDGET
}

async fn heartbeat_while<F, T, H>(operation: F, interval: Duration, mut heartbeat: H) -> T
where
    F: Future<Output = T>,
    H: FnMut(),
{
    tokio::pin!(operation);
    let first_tick = tokio::time::Instant::now() + interval;
    let mut ticker = tokio::time::interval_at(first_tick, interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            result = &mut operation => return result,
            _ = ticker.tick() => heartbeat(),
        }
    }
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
