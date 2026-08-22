use time::Duration;

use super::{EmailOutbox, EmailOutboxError};

const CLEANUP_BATCH: i64 = 500;
const PROCESSED_RETENTION: Duration = Duration::days(1);
const DEAD_LETTER_RETENTION: Duration = Duration::days(30);

impl EmailOutbox {
    pub(super) async fn prune_settled_outbox(&self) -> Result<u64, EmailOutboxError> {
        let processed = self
            .delete_expired(PROCESSED_QUERY, PROCESSED_RETENTION)
            .await?;
        let cancelled = self
            .delete_expired(CANCELLED_QUERY, PROCESSED_RETENTION)
            .await?;
        let dead_lettered = self
            .delete_expired(DEAD_LETTER_QUERY, DEAD_LETTER_RETENTION)
            .await?;
        Ok(processed
            .saturating_add(cancelled)
            .saturating_add(dead_lettered))
    }

    async fn delete_expired(
        &self,
        query: &str,
        retention: Duration,
    ) -> Result<u64, EmailOutboxError> {
        Ok(crate::sqlx::query(query)
            .bind(retention)
            .bind(CLEANUP_BATCH)
            .execute(&self.pool)
            .await
            .map_err(EmailOutboxError::Database)?
            .rows_affected())
    }
}

const PROCESSED_QUERY: &str = "WITH expired AS (
    SELECT id FROM email_outbox
    WHERE processed_at IS NOT NULL AND processed_at < NOW() - $1
    ORDER BY processed_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
)
DELETE FROM email_outbox AS outbox USING expired WHERE outbox.id = expired.id";

const CANCELLED_QUERY: &str = "WITH expired AS (
    SELECT id FROM email_outbox
    WHERE cancelled_at IS NOT NULL AND cancelled_at < NOW() - $1
    ORDER BY cancelled_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
)
DELETE FROM email_outbox AS outbox USING expired WHERE outbox.id = expired.id";

const DEAD_LETTER_QUERY: &str = "WITH expired AS (
    SELECT id FROM email_outbox
    WHERE dead_lettered_at IS NOT NULL AND dead_lettered_at < NOW() - $1
    ORDER BY dead_lettered_at, id LIMIT $2 FOR UPDATE SKIP LOCKED
)
DELETE FROM email_outbox AS outbox USING expired WHERE outbox.id = expired.id";
