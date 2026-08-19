-- Registration invitation admission control (Issue #554).
-- Plaintext codes are returned once and never persisted; only SHA-256 digests remain.
CREATE TABLE registration_invitation_codes (
    id BIGSERIAL PRIMARY KEY,
    code_digest BYTEA NOT NULL UNIQUE,
    label TEXT,
    max_uses INTEGER NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT registration_invitation_digest_check CHECK (octet_length(code_digest) = 32),
    CONSTRAINT registration_invitation_label_check CHECK (label IS NULL OR length(label) BETWEEN 1 AND 128),
    CONSTRAINT registration_invitation_max_uses_check CHECK (max_uses BETWEEN 1 AND 10000),
    CONSTRAINT registration_invitation_use_count_check CHECK (use_count BETWEEN 0 AND max_uses),
    CONSTRAINT registration_invitation_expiry_check CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE registration_invitation_uses (
    invitation_id BIGINT NOT NULL REFERENCES registration_invitation_codes(id) ON DELETE RESTRICT,
    user_id BIGINT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (invitation_id, user_id)
);

CREATE INDEX registration_invitation_codes_status_idx
    ON registration_invitation_codes (disabled_at, expires_at, created_at DESC);

GRANT SELECT, INSERT, UPDATE ON TABLE registration_invitation_codes TO chenxing_runtime;
GRANT SELECT, INSERT ON TABLE registration_invitation_uses TO chenxing_runtime;
GRANT USAGE, SELECT ON SEQUENCE registration_invitation_codes_id_seq TO chenxing_runtime;
