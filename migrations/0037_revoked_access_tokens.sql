-- Issue #656: persist access-token revocation as a durable PostgreSQL fact.
--
-- Access tokens are self-contained JWTs. Revoking one previously wrote only a
-- Redis marker keyed by SHA-256(token) with TTL = remaining token lifetime.
-- A flush, eviction, or failover that dropped that marker made JWT validation
-- succeed again and UserInfo served the profile until expiry.
--
-- PostgreSQL is the durable fact store. Redis remains a fast-path cache:
-- a hit of the marker still rejects immediately; a miss (or Redis failure)
-- falls back to this table. Lookup is existence-only — `expires_at` is a
-- reap hint, not a validity gate, so an early reap cannot resurrect a token
-- that JWT `exp` still accepts. Rows may be deleted once `expires_at < NOW()`.
--
-- The raw token is never stored. The identifier is the 32-byte SHA-256 digest
-- already used for the Redis key.
CREATE TABLE revoked_access_tokens (
    token_hash BYTEA PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT revoked_access_tokens_hash_check CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX revoked_access_tokens_expires_at_idx
    ON revoked_access_tokens (expires_at);

COMMENT ON TABLE revoked_access_tokens IS
    'Durable access-token revocation; Redis is a TTL cache in front of this table';
COMMENT ON COLUMN revoked_access_tokens.token_hash IS
    'SHA-256 digest of the access token; the raw token is never stored';
COMMENT ON COLUMN revoked_access_tokens.expires_at IS
    'Token expiry copied at revoke time so expired rows can be reaped';

GRANT SELECT, INSERT, DELETE ON TABLE revoked_access_tokens TO chenxing_runtime;
