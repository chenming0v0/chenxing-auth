ALTER TABLE users
    ADD COLUMN session_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE user_sessions
    ADD COLUMN session_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE session_outbox
    ADD COLUMN generation BIGINT NOT NULL DEFAULT 0;

CREATE INDEX user_sessions_user_epoch_idx
    ON user_sessions (user_id, session_epoch);
