use super::{EmailOutbox, EmailOutboxError, MAX_FAILED_ATTEMPTS, OutboxEntry};

impl EmailOutbox {
    pub(super) async fn record_failure(
        &self,
        entry: &OutboxEntry,
        error_value: &EmailOutboxError,
    ) -> Result<(), EmailOutboxError> {
        let error_code = error_value.failure_code();
        // 数据库故障无法证明投递失败，尤其 SMTP 已接受后的终态写入失败。
        // 保留至少一次投递语义：这类不确定结果只安排重试，不消耗失败预算。
        let failure_increment = if matches!(error_value, EmailOutboxError::Database(_)) {
            0
        } else {
            1
        };
        let delay_seconds = retry_delay_seconds(entry.failed_attempts + failure_increment);
        // 累加与死信判断在同一条围栏更新内完成；旧领取者和重复回报均不增加计数。
        let outcome: Option<(i32, bool)> = crate::sqlx::query_as(
            "UPDATE email_outbox
             SET failed_attempts = failed_attempts + $4,
                 dead_lettered_at = CASE
                     WHEN $4 > 0 AND failed_attempts + $4 >= $5 THEN NOW()
                     ELSE dead_lettered_at
                 END,
                 available_at = NOW() + $6, claim_token = '', last_error = $7
             WHERE id = $1 AND processed_at IS NULL AND cancelled_at IS NULL
               AND dead_lettered_at IS NULL
               AND claim_generation = $2 AND claim_token = $3
             RETURNING failed_attempts, dead_lettered_at IS NOT NULL",
        )
        .bind(entry.id)
        .bind(entry.claim_generation)
        .bind(&entry.claim_token)
        .bind(failure_increment)
        .bind(MAX_FAILED_ATTEMPTS)
        .bind(time::Duration::seconds(delay_seconds))
        .bind(error_code)
        .fetch_optional(&self.pool)
        .await
        .map_err(EmailOutboxError::Database)?;
        match outcome {
            None => tracing::warn!(
                outbox_id = entry.id,
                claim_generation = entry.claim_generation,
                kind = %entry.kind,
                event = "email_outbox.stale_claim",
                "stale email outbox failure ignored"
            ),
            Some((failed_attempts, false)) => tracing::warn!(
                event = "email_outbox.retry_scheduled",
                delivery_semantics = super::DELIVERY_SEMANTICS,
                outbox_id = entry.id,
                kind = %entry.kind,
                attempt = entry.attempts,
                failed_attempts,
                retry_after_seconds = delay_seconds,
                error_kind = error_code,
                "email outbox event remains pending for retry"
            ),
            Some((failed_attempts, true)) => tracing::error!(
                event = "email_outbox.dead_lettered",
                delivery_semantics = super::DELIVERY_SEMANTICS,
                outbox_id = entry.id,
                kind = %entry.kind,
                attempt = entry.attempts,
                failed_attempts,
                error_kind = error_code,
                "email outbox event exhausted retries and was moved to dead-letter"
            ),
        }
        Ok(())
    }
}

fn retry_delay_seconds(failed_attempts: i32) -> i64 {
    if failed_attempts <= 1 {
        1
    } else {
        2_i64.saturating_pow((failed_attempts - 1) as u32).min(300)
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
