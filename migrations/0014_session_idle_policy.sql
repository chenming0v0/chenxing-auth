-- Issue #167: persist the last successful session activity separately from
-- the absolute expiry. The backfill preserves the age of existing sessions;
-- it does not grant them a fresh seven-day absolute lifetime.
--
-- Rollback note: stop the application before dropping this column. The
-- application must be rolled back first so no request attempts to read or
-- write last_seen_at.

ALTER TABLE user_sessions
    ADD COLUMN last_seen_at TIMESTAMPTZ;

UPDATE user_sessions
SET last_seen_at = created_at
WHERE last_seen_at IS NULL;

ALTER TABLE user_sessions
    ALTER COLUMN last_seen_at SET DEFAULT NOW(),
    ALTER COLUMN last_seen_at SET NOT NULL;

CREATE INDEX user_sessions_active_created_idx
    ON user_sessions (user_id, created_at ASC, id ASC)
    WHERE revoked_at IS NULL;
