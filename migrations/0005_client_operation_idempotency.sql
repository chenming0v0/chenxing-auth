-- Durable recovery for one-time Client credentials (Issue #50).
--
-- The raw Idempotency-Key and plaintext Client Secret are never stored. The
-- request key is represented by a SHA-256 digest; the secret is reconstructed
-- from the caller-supplied key and the retained AUTH_ENCRYPTION_KEYS entry.
CREATE TABLE client_operation_idempotency (
    actor_scope TEXT NOT NULL,
    key_digest BYTEA NOT NULL,
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    secret_kid TEXT NOT NULL,
    result_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (actor_scope, key_digest),
    CONSTRAINT client_operation_idempotency_actor_scope_check
        CHECK (length(actor_scope) BETWEEN 1 AND 128),
    CONSTRAINT client_operation_idempotency_key_digest_check
        CHECK (octet_length(key_digest) = 32),
    CONSTRAINT client_operation_idempotency_operation_check
        CHECK (operation IN ('client.create', 'client.rotate')),
    CONSTRAINT client_operation_idempotency_request_hash_check
        CHECK (octet_length(request_hash) = 32),
    CONSTRAINT client_operation_idempotency_secret_kid_check
        CHECK (length(secret_kid) BETWEEN 1 AND 64),
    CONSTRAINT client_operation_idempotency_result_check
        CHECK (
            (result_data IS NULL AND completed_at IS NULL)
            OR (jsonb_typeof(result_data) = 'object' AND completed_at IS NOT NULL)
        ),
    CONSTRAINT client_operation_idempotency_expiry_check
        CHECK (expires_at > created_at)
);

CREATE INDEX client_operation_idempotency_expiry_idx
    ON client_operation_idempotency (actor_scope, expires_at);
