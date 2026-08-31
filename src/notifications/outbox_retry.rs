use super::{EmailOutbox, EmailOutboxError, MAX_ATTEMPTS, OutboxEntry};

impl EmailOutbox {
    pub(super) async fn record_failure(
        &self,
        entry: &OutboxEntry,
        error_value: &EmailOutboxError,
    ) -> Result<(), EmailOutboxError> {
        let error_code = error_value.failure_code();
        let retry_after_seconds = if entry.attempts >= MAX_ATTEMPTS {
            None
        } else {
            Some(retry_delay_seconds(entry.attempts))
        };
        let outcome = match retry_after_seconds {
            None => crate::sqlx::query(
                "UPDATE email_outbox
                 SET dead_lettered_at = NOW(), claim_token = '', last_error = $4
                 WHERE id = $1 AND processed_at IS NULL AND cancelled_at IS NULL
                   AND dead_lettered_at IS NULL
                   AND claim_generation = $2 AND claim_token = $3",
            )
            .bind(entry.id)
            .bind(entry.claim_generation)
            .bind(&entry.claim_token)
            .bind(error_code)
            .execute(&self.pool)
            .await
            .map_err(EmailOutboxError::Database)?,
            Some(delay_seconds) => crate::sqlx::query(
                "UPDATE email_outbox
                 SET available_at = NOW() + $4, claim_token = '', last_error = $5
                 WHERE id = $1 AND processed_at IS NULL AND cancelled_at IS NULL
                   AND dead_lettered_at IS NULL
                   AND claim_generation = $2 AND claim_token = $3",
            )
            .bind(entry.id)
            .bind(entry.claim_generation)
            .bind(&entry.claim_token)
            .bind(time::Duration::seconds(delay_seconds))
            .bind(error_code)
            .execute(&self.pool)
            .await
            .map_err(EmailOutboxError::Database)?,
        };
        if outcome.rows_affected() == 0 {
            tracing::warn!(
                outbox_id = entry.id,
                claim_generation = entry.claim_generation,
                kind = %entry.kind,
                event = "email_outbox.stale_claim",
                "stale email outbox failure ignored"
            );
        } else if let Some(delay_seconds) = retry_after_seconds {
            tracing::warn!(
                event = "email_outbox.retry_scheduled",
                delivery_semantics = super::DELIVERY_SEMANTICS,
                outbox_id = entry.id,
                kind = %entry.kind,
                attempt = entry.attempts,
                retry_after_seconds = delay_seconds,
                error_kind = error_code,
                "email outbox event remains pending for retry"
            );
        } else {
            tracing::error!(
                event = "email_outbox.dead_lettered",
                delivery_semantics = super::DELIVERY_SEMANTICS,
                outbox_id = entry.id,
                kind = %entry.kind,
                attempt = entry.attempts,
                error_kind = error_code,
                "email outbox event exhausted retries and was moved to dead-letter"
            );
        }
        Ok(())
    }
}

fn retry_delay_seconds(attempts: i32) -> i64 {
    if attempts <= 1 {
        1
    } else {
        2_i64.saturating_pow((attempts - 1) as u32).min(300)
    }
}

#[cfg(test)]
mod tests {
    use super::retry_delay_seconds;

    #[test]
    fn retry_delay_is_bounded_and_starts_at_one_second() {
        assert_eq!(retry_delay_seconds(0), 1);
        assert_eq!(retry_delay_seconds(1), 1);
        assert_eq!(retry_delay_seconds(2), 2);
        assert_eq!(retry_delay_seconds(9), 256);
        assert_eq!(retry_delay_seconds(10), 300);
        assert_eq!(retry_delay_seconds(i32::MAX), 300);
    }
}
