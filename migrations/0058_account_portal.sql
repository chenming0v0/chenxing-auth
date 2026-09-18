-- Account Provider v1 消费方表。独立于旧 linked_accounts / account_providers
-- 注册表：旧二进制忽略这些表，回滚只保留增量迁移、不删库。
--
-- 0032 取消了未来表的默认写权限，运行时角色必须显式 GRANT。

CREATE TABLE account_portal_providers (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_ciphertext TEXT NOT NULL,
    identifier_label TEXT NOT NULL,
    secret_label TEXT NOT NULL,
    identifier_sensitive BOOLEAN NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_portal_providers_display_name_check
        CHECK (display_name <> '' AND char_length(display_name) <= 128),
    CONSTRAINT account_portal_providers_issuer_check
        CHECK (
            issuer LIKE 'https://%'
            AND char_length(issuer) BETWEEN 8 AND 255
            AND position('/' in substring(issuer from 9)) = 0
            AND position('?' in issuer) = 0
            AND position('#' in issuer) = 0
            AND position('@' in issuer) = 0
        ),
    CONSTRAINT account_portal_providers_client_id_check
        CHECK (
            client_id <> ''
            AND char_length(client_id) <= 512
            AND position(':' in client_id) = 0
        ),
    CONSTRAINT account_portal_providers_secret_check
        CHECK (octet_length(client_secret_ciphertext) > 0),
    CONSTRAINT account_portal_providers_identifier_label_check
        CHECK (identifier_label <> '' AND char_length(identifier_label) <= 128),
    CONSTRAINT account_portal_providers_secret_label_check
        CHECK (secret_label <> '' AND char_length(secret_label) <= 128),
    CONSTRAINT account_portal_providers_revision_check CHECK (revision >= 1),
    CONSTRAINT account_portal_providers_issuer_key UNIQUE (issuer)
);

CREATE TABLE account_portal_bindings (
    id UUID PRIMARY KEY,
    provider_id UUID NOT NULL REFERENCES account_portal_providers (id),
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    uid TEXT NOT NULL DEFAULT '',
    issuer TEXT NOT NULL,
    grant_id UUID,
    grant_expires_at TIMESTAMPTZ,
    generation BIGINT NOT NULL DEFAULT 1,
    tombstoned_at TIMESTAMPTZ,
    token_bundle_ciphertext TEXT,
    snapshot_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    access_expires_at TIMESTAMPTZ,
    refresh_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_portal_bindings_uid_check
        CHECK (char_length(uid) <= 255),
    CONSTRAINT account_portal_bindings_issuer_check
        CHECK (issuer <> '' AND char_length(issuer) <= 255),
    CONSTRAINT account_portal_bindings_generation_check CHECK (generation >= 1),
    CONSTRAINT account_portal_bindings_snapshot_size_check
        CHECK (octet_length(snapshot_json::text) <= 131072)
);

CREATE UNIQUE INDEX account_portal_bindings_live_provider_user
    ON account_portal_bindings (provider_id, user_id)
    WHERE tombstoned_at IS NULL;

CREATE UNIQUE INDEX account_portal_bindings_live_provider_uid
    ON account_portal_bindings (provider_id, uid)
    WHERE tombstoned_at IS NULL AND uid <> '';

CREATE INDEX account_portal_bindings_user_id_idx
    ON account_portal_bindings (user_id)
    WHERE tombstoned_at IS NULL;

CREATE TABLE account_portal_operations (
    idempotency_key UUID NOT NULL,
    provider_id UUID NOT NULL REFERENCES account_portal_providers (id),
    binding_id UUID NOT NULL,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    operation_type TEXT NOT NULL,
    status TEXT NOT NULL,
    lease_until TIMESTAMPTZ,
    request_fingerprint TEXT NOT NULL,
    provider_revision BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    committed_at TIMESTAMPTZ,
    CONSTRAINT account_portal_operations_type_check
        CHECK (operation_type IN ('create', 'refresh', 'revoke')),
    CONSTRAINT account_portal_operations_status_check
        CHECK (status IN ('leased', 'committed', 'failed')),
    CONSTRAINT account_portal_operations_fingerprint_check
        CHECK (request_fingerprint <> '' AND char_length(request_fingerprint) <= 128),
    CONSTRAINT account_portal_operations_pkey
        PRIMARY KEY (provider_id, operation_type, idempotency_key),
    CONSTRAINT account_portal_operations_binding_fk
        FOREIGN KEY (binding_id) REFERENCES account_portal_bindings (id) ON DELETE CASCADE
);

CREATE INDEX account_portal_operations_binding_idx
    ON account_portal_operations (binding_id, created_at);

CREATE TABLE account_portal_revocation_outbox (
    id UUID PRIMARY KEY,
    provider_id UUID NOT NULL REFERENCES account_portal_providers (id),
    binding_id UUID NOT NULL REFERENCES account_portal_bindings (id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_portal_revocation_outbox_attempts_check CHECK (attempts >= 0),
    CONSTRAINT account_portal_revocation_outbox_binding_key UNIQUE (binding_id)
);

CREATE INDEX account_portal_revocation_outbox_pending_idx
    ON account_portal_revocation_outbox (available_at, id)
    WHERE processed_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_portal_providers TO chenxing_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_portal_bindings TO chenxing_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_portal_operations TO chenxing_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE account_portal_revocation_outbox TO chenxing_runtime;
