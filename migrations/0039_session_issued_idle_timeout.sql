-- Issue #644: persist the idle window that was in force when the session was
-- issued. Lookup compares last_seen_at against this column, not the process
-- boot policy or the current admin setting.
--
-- Existing rows have no issuance-time value. They were evaluated against the
-- historical SessionPolicy default (1800s). Stamping that default keeps those
-- sessions on the window they already had; it must not pick up a later admin
-- change from app_settings (that would apply the new policy retroactively).
--
-- The column default is the same historical value so fixture INSERTs that omit
-- the column remain valid. Application issuance always writes the real window.
--
-- Rollback note: stop the application before dropping this column. The
-- application must be rolled back first so no request attempts to read or
-- write idle_timeout_seconds.

ALTER TABLE user_sessions
    ADD COLUMN idle_timeout_seconds BIGINT;

UPDATE user_sessions
SET idle_timeout_seconds = 1800
WHERE idle_timeout_seconds IS NULL;

ALTER TABLE user_sessions
    ALTER COLUMN idle_timeout_seconds SET DEFAULT 1800,
    ALTER COLUMN idle_timeout_seconds SET NOT NULL,
    ADD CONSTRAINT user_sessions_idle_timeout_seconds_range
        CHECK (idle_timeout_seconds >= 1 AND idle_timeout_seconds <= 2592000);
