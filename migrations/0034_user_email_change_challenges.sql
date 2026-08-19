CREATE TABLE user_email_change_challenges (
    id UUID PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    new_email TEXT NOT NULL,
    new_canonical_email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    security_epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX user_email_change_one_pending_per_user
    ON user_email_change_challenges (user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX user_email_change_pending_expiry
    ON user_email_change_challenges (expires_at)
    WHERE consumed_at IS NULL;
