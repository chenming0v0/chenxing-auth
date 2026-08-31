-- Durable replay records for wallet purchase mutations.
-- The raw key is never persisted; only its SHA-256 digest and a request
-- fingerprint are stored with the committed response.
CREATE TABLE wallet_purchase_idempotency (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    key_digest BYTEA NOT NULL,
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    result_data JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, key_digest),
    CONSTRAINT wallet_purchase_idempotency_key_digest_check CHECK (octet_length(key_digest) = 32),
    CONSTRAINT wallet_purchase_idempotency_request_hash_check CHECK (octet_length(request_hash) = 32),
    CONSTRAINT wallet_purchase_idempotency_result_state_check CHECK (
        (result_data IS NULL AND completed_at IS NULL)
        OR (result_data IS NOT NULL AND completed_at IS NOT NULL)
    )
);
CREATE INDEX wallet_purchase_idempotency_expiry_idx
    ON wallet_purchase_idempotency (expires_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE wallet_purchase_idempotency TO chenxing_runtime;
