-- Issue #275: give session_outbox a bounded lifecycle.
--
-- Three defects share one root cause: the table only had a "pending vs done"
-- flag and no terminal state for work that will never succeed.
--
--   1. Rows with processed_at set were never deleted, so the table grew for the
--      lifetime of the deployment. Every login, renewal and revocation appends
--      at least one row.
--   2. A delivery that keeps failing was rescheduled forever. The backoff caps
--      at five minutes, so a permanently broken event is re-claimed every five
--      minutes for as long as the deployment lives, and it stays at the head of
--      the pending index because claiming is ordered by id.
--   3. Nothing distinguished "waiting for a retry" from "gave up", so an
--      operator could not query what actually needs attention.
--
-- The model here has exactly three states, derived from two nullable
-- timestamps and pinned by a CHECK so no row can claim two of them:
--
--   pending      processed_at IS NULL     AND dead_lettered_at IS NULL
--   processed    processed_at IS NOT NULL AND dead_lettered_at IS NULL
--   dead_letter  processed_at IS NULL     AND dead_lettered_at IS NOT NULL
--
-- Both terminal states are pruned by the application in bounded batches, with
-- separate retention windows: processed rows carry no diagnostic value beyond a
-- short forensic window, while dead-lettered rows are the audit record of lost
-- Redis projections and are kept much longer.
--
-- Rollback note: this migration is data-preserving and reversible without data
-- loss. To roll back, drop the two cleanup indexes, drop the state check
-- constraint, drop the dead_lettered_at column, then restore the original
-- session_outbox_pending_idx definition:
--
--   DROP INDEX session_outbox_processed_cleanup_idx;
--   DROP INDEX session_outbox_dead_letter_idx;
--   DROP INDEX session_outbox_pending_idx;
--   ALTER TABLE session_outbox
--       DROP CONSTRAINT session_outbox_state_check,
--       DROP COLUMN dead_lettered_at;
--   CREATE INDEX session_outbox_pending_idx
--       ON session_outbox (available_at, id)
--       WHERE processed_at IS NULL;
--
-- Rolling back re-exposes dead-lettered rows to the claim query, which resumes
-- retrying them. That is the pre-migration behaviour, not new damage. Before
-- rolling back, export dead-lettered rows if the failure history still matters:
-- the column drop discards dead_lettered_at, and last_error alone cannot
-- distinguish "gave up" from "will retry".
--
-- Operational note: the index rebuild below takes an ACCESS EXCLUSIVE lock on
-- session_outbox. On a deployment that has been accumulating processed rows
-- since 0003 this table can be large, so the migration may block outbox
-- delivery for the duration of the build. Delivery is asynchronous and the
-- worker retries, so the effect is delayed Redis projection rather than failed
-- requests. Nothing on the authentication path reads this table. Operators with
-- an unusually large table can instead build the replacements CONCURRENTLY
-- outside a transaction before applying this migration.

ALTER TABLE session_outbox
    ADD COLUMN dead_lettered_at TIMESTAMPTZ;

-- Existing rows are either pending or processed, so the constraint is satisfied
-- by every row already in the table and validates without a rewrite pass.
ALTER TABLE session_outbox
    ADD CONSTRAINT session_outbox_state_check
        CHECK (processed_at IS NULL OR dead_lettered_at IS NULL);

-- The claim query must stop seeing dead-lettered rows. Keeping them in the
-- pending index is what made a permanently failing event re-claimable forever:
-- it sorts by id, so the oldest broken row is picked first on every pass.
DROP INDEX session_outbox_pending_idx;
CREATE INDEX session_outbox_pending_idx
    ON session_outbox (available_at, id)
    WHERE processed_at IS NULL AND dead_lettered_at IS NULL;

-- One partial index per terminal state. Cleanup scans a single class at a time
-- with its own retention window, so a shared index would force a filter step on
-- rows the batch cannot delete anyway.
CREATE INDEX session_outbox_processed_cleanup_idx
    ON session_outbox (processed_at, id)
    WHERE processed_at IS NOT NULL;

CREATE INDEX session_outbox_dead_letter_idx
    ON session_outbox (dead_lettered_at, id)
    WHERE dead_lettered_at IS NOT NULL;

COMMENT ON COLUMN session_outbox.dead_lettered_at IS
    'Set when delivery exhausted the attempt budget; the row is a terminal audit record and is never claimed again';
COMMENT ON COLUMN session_outbox.processed_at IS
    'Set when the Redis projection succeeded; the row is terminal and is pruned after the processed retention window';
