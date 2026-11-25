//! 邮件领取和终态写入共用代次与令牌围栏，SMTP 等待期间不占用数据库事务。

use uuid::Uuid;

use super::{EmailOutbox, EmailOutboxError, OUTBOX_LEASE, OutboxEntry};
use crate::{
    sqlx::{Postgres, Transaction},
    users::domain::UserId,
};

type OutboxClaimRow = (i64, UserId, Uuid, String, i32, i32, i64, String);

impl EmailOutbox {
    pub(super) async fn claim(&self) -> Result<Option<OutboxEntry>, EmailOutboxError> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(EmailOutboxError::Database)?;
        let claim_token = Uuid::new_v4().simple().to_string();
        let row: Option<OutboxClaimRow> = crate::sqlx::query_as(
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
                       outbox.attempts, outbox.failed_attempts,
                       outbox.claim_generation, outbox.claim_token",
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
            |(
                id,
                user_id,
                challenge_id,
                kind,
                attempts,
                failed_attempts,
                claim_generation,
                claim_token,
            )| {
                OutboxEntry {
                    id,
                    user_id,
                    challenge_id,
                    kind,
                    attempts,
                    failed_attempts,
                    claim_generation,
                    claim_token,
                }
            },
        ))
    }

    pub(super) async fn mark_processed(
        &self,
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
        .execute(&self.pool)
        .await
        .map_err(EmailOutboxError::Database)?;
        Ok(result.rows_affected() == 1)
    }

    pub(super) async fn mark_cancelled(
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
