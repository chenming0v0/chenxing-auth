-- Issue #664: persist email delivery work with the email-change challenge.
-- The code is encrypted under AUTH_ENCRYPTION_KEYS; it must never be stored as
-- plaintext in PostgreSQL, logs, or a generic session outbox payload.
ALTER TABLE user_email_change_challenges
    ADD CONSTRAINT user_email_change_challenge_id_user_key UNIQUE (id, user_id);

CREATE TABLE email_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_id UUID NOT NULL,
    encrypted_code BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_generation BIGINT NOT NULL DEFAULT 0,
    claim_token TEXT NOT NULL DEFAULT '',
    processed_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    dead_lettered_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT email_outbox_terminal_state_check CHECK (
        num_nonnulls(processed_at, cancelled_at, dead_lettered_at) <= 1
    ),
    CONSTRAINT email_outbox_attempts_check CHECK (attempts >= 0),
    CONSTRAINT email_outbox_code_check
        CHECK (octet_length(encrypted_code) > 0),
    CONSTRAINT email_outbox_one_event_per_challenge UNIQUE (challenge_id),
    CONSTRAINT email_outbox_challenge_user_fkey
        FOREIGN KEY (challenge_id, user_id)
        REFERENCES user_email_change_challenges (id, user_id)
        ON DELETE CASCADE
);

CREATE INDEX email_outbox_pending_idx
    ON email_outbox (available_at, id)
    WHERE processed_at IS NULL
      AND cancelled_at IS NULL
      AND dead_lettered_at IS NULL;

CREATE INDEX email_outbox_processed_idx
    ON email_outbox (processed_at, id)
    WHERE processed_at IS NOT NULL;

CREATE INDEX email_outbox_cancelled_idx
    ON email_outbox (cancelled_at, id)
    WHERE cancelled_at IS NOT NULL;

CREATE INDEX email_outbox_dead_letter_idx
    ON email_outbox (dead_lettered_at, id)
    WHERE dead_lettered_at IS NOT NULL;

-- 0032 removed write privileges from future tables. The runtime role needs
-- exactly the outbox CRUD required by the request path and worker retention.
DO $$
DECLARE
    target_schema text := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE %I.email_outbox TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'GRANT USAGE, SELECT ON SEQUENCE %I.email_outbox_id_seq TO chenxing_runtime',
        target_schema
    );
END
$$;
