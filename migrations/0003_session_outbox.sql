ALTER TABLE user_sessions
    ADD COLUMN session_payload BYTEA;

CREATE TABLE session_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation TEXT NOT NULL,
    session_id BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    token_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT session_outbox_operation_check
        CHECK (operation IN ('sync_session', 'revoke_session', 'revoke_user')),
    CONSTRAINT session_outbox_target_check
        CHECK (
            (operation = 'revoke_user' AND user_id IS NOT NULL)
            OR (operation IN ('sync_session', 'revoke_session') AND token_hash IS NOT NULL)
        )
);

CREATE INDEX session_outbox_pending_idx
    ON session_outbox (available_at, id)
    WHERE processed_at IS NULL;

CREATE INDEX session_outbox_user_idx
    ON session_outbox (user_id, created_at)
    WHERE operation = 'revoke_user' AND processed_at IS NULL;
