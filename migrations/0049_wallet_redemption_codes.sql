-- Wallet redemption codes grant internal 辰星点. Plaintext is returned once;
-- only a SHA-256 digest is persisted.
-- Rollback: DROP TABLE wallet_redemptions; DROP TABLE wallet_redemption_codes;
CREATE TABLE wallet_redemption_codes (
    id BIGSERIAL PRIMARY KEY,
    code_digest BYTEA NOT NULL UNIQUE,
    label TEXT,
    points BIGINT NOT NULL,
    max_uses INTEGER NOT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ,
    disabled_at TIMESTAMPTZ,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT wallet_redemption_digest_check CHECK (octet_length(code_digest) = 32),
    CONSTRAINT wallet_redemption_label_check CHECK (label IS NULL OR length(label) BETWEEN 1 AND 128),
    CONSTRAINT wallet_redemption_points_check CHECK (points BETWEEN 1 AND 1000000000),
    CONSTRAINT wallet_redemption_max_uses_check CHECK (max_uses BETWEEN 1 AND 10000),
    CONSTRAINT wallet_redemption_use_count_check CHECK (use_count BETWEEN 0 AND max_uses),
    CONSTRAINT wallet_redemption_expiry_check CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE wallet_redemptions (
    code_id BIGINT NOT NULL REFERENCES wallet_redemption_codes(id) ON DELETE RESTRICT,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    points BIGINT NOT NULL,
    redeemed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (code_id, user_id),
    CONSTRAINT wallet_redemptions_points_check CHECK (points > 0)
);

CREATE INDEX wallet_redemption_codes_status_idx
    ON wallet_redemption_codes (disabled_at, expires_at, created_at DESC, id DESC);
CREATE INDEX wallet_redemptions_user_idx
    ON wallet_redemptions (user_id, redeemed_at DESC);

GRANT SELECT, INSERT, UPDATE ON TABLE wallet_redemption_codes TO chenxing_runtime;
GRANT SELECT, INSERT ON TABLE wallet_redemptions TO chenxing_runtime;
GRANT USAGE, SELECT ON SEQUENCE wallet_redemption_codes_id_seq TO chenxing_runtime;
