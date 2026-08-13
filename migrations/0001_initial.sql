-- Destructive development baseline.
--
-- This file describes the complete current database state. It intentionally
-- does not upgrade databases that ran an earlier migration chain. Recreate the
-- database before applying this baseline.

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE TABLE plans (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    oauth_clients_limit INTEGER NOT NULL DEFAULT 2,
    daily_auth_limit BIGINT NOT NULL DEFAULT 2500,
    monthly_auth_limit BIGINT,
    max_qps INTEGER,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT plans_status_check CHECK (status IN ('active', 'archived')),
    CONSTRAINT plans_default_must_be_active
        CHECK (status = 'active' OR is_default = FALSE)
);

CREATE UNIQUE INDEX plans_single_default_idx
    ON plans (is_default)
    WHERE is_default = TRUE;

CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    canonical_email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    password_login_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    plan_id BIGINT REFERENCES plans(id) ON DELETE SET NULL,
    plan_expires_at TIMESTAMPTZ,
    session_epoch BIGINT NOT NULL DEFAULT 0,
    avatar_data BYTEA,
    avatar_mime TEXT,
    avatar_updated_at TIMESTAMPTZ,
    CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'owner')),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT users_avatar_complete_check CHECK (
        (avatar_data IS NULL AND avatar_mime IS NULL AND avatar_updated_at IS NULL)
        OR (avatar_data IS NOT NULL AND avatar_mime IS NOT NULL AND avatar_updated_at IS NOT NULL)
    ),
    CONSTRAINT users_canonical_email_key UNIQUE (canonical_email)
);

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_role_idx ON users (role);
CREATE INDEX users_admin_query_order_idx ON users (created_at DESC, id DESC);
CREATE INDEX users_admin_query_status_idx ON users (status, created_at DESC, id DESC);
CREATE INDEX users_admin_search_trgm_idx
    ON users USING GIN (
        username public.gin_trgm_ops,
        email public.gin_trgm_ops,
        display_name public.gin_trgm_ops
    );

CREATE TABLE oauth_clients (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_name TEXT NOT NULL,
    client_secret_hash TEXT,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    status TEXT NOT NULL DEFAULT 'active',
    owner_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    client_secret_version BIGINT NOT NULL DEFAULT 0,
    allow_legacy_refresh_tokens BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT oauth_clients_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_clients_auth_method_check
        CHECK (auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    CONSTRAINT oauth_clients_client_secret_version_check
        CHECK (client_secret_version >= 0)
);

CREATE INDEX oauth_clients_owner_user_id_idx
    ON oauth_clients (owner_user_id, created_at DESC);
CREATE INDEX oauth_clients_admin_query_order_idx
    ON oauth_clients (created_at DESC, id DESC);
CREATE INDEX oauth_clients_admin_query_status_idx
    ON oauth_clients (status, created_at DESC, id DESC);
CREATE INDEX oauth_clients_admin_search_trgm_idx
    ON oauth_clients USING GIN (
        client_id public.gin_trgm_ops,
        client_name public.gin_trgm_ops
    );

CREATE TABLE user_consents (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    state_version BIGINT NOT NULL DEFAULT 1,
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE user_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    session_payload BYTEA,
    session_epoch BIGINT NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX user_sessions_user_created_idx
    ON user_sessions (user_id, created_at DESC);
CREATE INDEX user_sessions_user_epoch_idx
    ON user_sessions (user_id, session_epoch);
CREATE INDEX user_sessions_active_created_idx
    ON user_sessions (user_id, created_at ASC, id ASC)
    WHERE revoked_at IS NULL;

CREATE TABLE user_totp_factors (
    user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_passkeys (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    credential JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX user_passkeys_user_idx
    ON user_passkeys (user_id, created_at DESC);

CREATE TABLE oauth_providers (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    authorization_endpoint TEXT NOT NULL,
    token_endpoint TEXT NOT NULL,
    userinfo_endpoint TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_ciphertext BYTEA NOT NULL DEFAULT ''::bytea,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    subject_claim TEXT NOT NULL DEFAULT 'sub',
    email_claim TEXT NOT NULL DEFAULT 'email',
    name_claim TEXT,
    email_verified_claim TEXT,
    client_auth_method TEXT NOT NULL DEFAULT 'basic',
    status TEXT NOT NULL DEFAULT 'disabled',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    pkce_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    CONSTRAINT oauth_providers_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_providers_client_auth_check
        CHECK (client_auth_method IN ('basic', 'request_body')),
    CONSTRAINT oauth_providers_active_requires_email_verified_claim CHECK (
        status <> 'active'
        OR (email_verified_claim IS NOT NULL AND btrim(email_verified_claim) <> '')
    )
);

CREATE INDEX oauth_providers_status_idx ON oauth_providers (status);

CREATE TABLE oauth_external_identities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider_id BIGINT NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider_id, subject),
    UNIQUE (provider_id, user_id)
);

CREATE INDEX oauth_external_identities_user_idx
    ON oauth_external_identities (user_id);

-- actor_user_id is deliberately not a foreign key. Deleting a user must not
-- issue an implicit UPDATE against the append-only audit log.
CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_user_id BIGINT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at DESC);
CREATE INDEX audit_events_resource_idx ON audit_events (resource_type, resource_id);
CREATE INDEX audit_events_actor_user_idx
    ON audit_events (actor_user_id, created_at DESC);
CREATE INDEX audit_events_action_idx
    ON audit_events (action, created_at DESC, id DESC);

CREATE TABLE app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

-- user_id is historical event data, not a live reference. Outbox tombstones
-- may also have every target cleared after the referenced row is deleted.
CREATE TABLE session_outbox (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    operation TEXT NOT NULL,
    session_id BIGINT REFERENCES user_sessions(id) ON DELETE SET NULL,
    user_id BIGINT,
    token_hash BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    generation BIGINT NOT NULL DEFAULT 0,
    dead_lettered_at TIMESTAMPTZ,
    CONSTRAINT session_outbox_operation_check
        CHECK (operation IN ('sync_session', 'revoke_session', 'revoke_user')),
    CONSTRAINT session_outbox_target_check CHECK (
        (operation = 'revoke_user' AND user_id IS NOT NULL)
        OR (operation IN ('sync_session', 'revoke_session') AND token_hash IS NOT NULL)
        OR (session_id IS NULL AND user_id IS NULL AND token_hash IS NULL)
    ),
    CONSTRAINT session_outbox_state_check
        CHECK (processed_at IS NULL OR dead_lettered_at IS NULL)
);

CREATE INDEX session_outbox_pending_idx
    ON session_outbox (available_at, id)
    WHERE processed_at IS NULL AND dead_lettered_at IS NULL;
CREATE INDEX session_outbox_user_idx
    ON session_outbox (user_id, created_at)
    WHERE operation = 'revoke_user' AND processed_at IS NULL;
CREATE INDEX session_outbox_processed_cleanup_idx
    ON session_outbox (processed_at, id)
    WHERE processed_at IS NOT NULL;
CREATE INDEX session_outbox_dead_letter_idx
    ON session_outbox (dead_lettered_at, id)
    WHERE dead_lettered_at IS NOT NULL;

COMMENT ON COLUMN session_outbox.dead_lettered_at IS
    'Set when delivery exhausted the attempt budget; the row is a terminal audit record and is never claimed again';
COMMENT ON COLUMN session_outbox.processed_at IS
    'Set when the Redis projection succeeded; the row is terminal and is pruned after the processed retention window';

CREATE TABLE audit_events_archive (
    id BIGINT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_user_id BIGINT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    archived_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX audit_events_archive_created_at_idx
    ON audit_events_archive (created_at DESC, id DESC);
CREATE INDEX audit_events_archive_action_idx
    ON audit_events_archive (action, created_at DESC, id DESC);
CREATE INDEX audit_events_archive_resource_idx
    ON audit_events_archive (resource_type, resource_id);
CREATE INDEX audit_events_archive_actor_user_idx
    ON audit_events_archive (actor_user_id, created_at DESC);

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'audit_events'
       AND TG_OP = 'DELETE'
       AND current_setting('chenxing.audit_events_archive', true) = 'on' THEN
        RETURN NULL;
    END IF;

    RAISE EXCEPTION 'audit event tables are append-only; % on %.% is not permitted',
        TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
        USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER audit_events_append_only_trigger
BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE TRIGGER audit_events_archive_append_only_trigger
BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events_archive
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE OR REPLACE FUNCTION archive_audit_events(
    p_retention_days INTEGER,
    p_batch_size INTEGER DEFAULT 1000
)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    archived_count INTEGER;
BEGIN
    IF p_retention_days < 1 OR p_retention_days > 36500 THEN
        RAISE EXCEPTION 'audit retention must be between 1 and 36500 days'
            USING ERRCODE = '22023';
    END IF;
    IF p_batch_size < 1 OR p_batch_size > 10000 THEN
        RAISE EXCEPTION 'audit archive batch size must be between 1 and 10000'
            USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtext('chenxing.audit_events.archive'));
    PERFORM set_config('chenxing.audit_events_archive', 'on', true);

    WITH candidates AS (
        SELECT id
        FROM audit_events
        WHERE created_at < CURRENT_TIMESTAMP - make_interval(days => p_retention_days)
        ORDER BY created_at, id
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    ), copied AS (
        INSERT INTO audit_events_archive
            (id, actor_type, actor_user_id, action, resource_type, resource_id,
             metadata, created_at)
        SELECT event.id, event.actor_type, event.actor_user_id, event.action,
               event.resource_type, event.resource_id, event.metadata, event.created_at
        FROM audit_events AS event
        JOIN candidates ON candidates.id = event.id
        ON CONFLICT (id) DO NOTHING
        RETURNING id
    )
    DELETE FROM audit_events AS event
    USING copied
    WHERE event.id = copied.id;

    GET DIAGNOSTICS archived_count = ROW_COUNT;
    PERFORM set_config('chenxing.audit_events_archive', 'off', true);
    RETURN archived_count;
END;
$$;

COMMENT ON TABLE audit_events_archive IS
    'Immutable audit events moved out of the hot table after the configured hot retention window';
COMMENT ON FUNCTION archive_audit_events(INTEGER, INTEGER) IS
    'Atomically copies old audit events to the immutable archive and removes only copied hot rows';

INSERT INTO plans (
    code,
    name,
    description,
    oauth_clients_limit,
    daily_auth_limit,
    monthly_auth_limit,
    max_qps,
    is_default,
    status
)
VALUES ('basic', '基础版', '默认套餐', 2, 2500, 50000, NULL, TRUE, 'active');

INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES
    ('registration_email_from', NULL, NOW()),
    ('passkey', NULL, NOW()),
    ('email_policy', NULL, NOW()),
    ('smtp', NULL, NOW()),
    ('security_limits', NULL, NOW());

-- The runtime role is a cluster object and is provisioned immediately before
-- this transactional baseline. Everything below remains schema-local.
DO $$
DECLARE
    target_schema TEXT := current_schema();
    users_id_sequence TEXT := pg_get_serial_sequence('users', 'id');
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO chenxing_runtime', target_schema);
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'REVOKE UPDATE, DELETE, TRUNCATE ON %I.audit_events FROM chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'REVOKE UPDATE, DELETE, TRUNCATE ON %I.audit_events_archive FROM chenxing_runtime',
        target_schema
    );

    IF users_id_sequence IS NULL THEN
        RAISE EXCEPTION 'users.id has no owned sequence; cannot grant runtime setval';
    END IF;
    EXECUTE format('GRANT UPDATE ON SEQUENCE %s TO chenxing_runtime', users_id_sequence);

    EXECUTE format(
        'ALTER FUNCTION archive_audit_events(INTEGER, INTEGER)
             SECURITY DEFINER
             SET search_path = pg_catalog, %I',
        target_schema
    );
    EXECUTE format(
        'REVOKE ALL ON FUNCTION %I.archive_audit_events(INTEGER, INTEGER) FROM PUBLIC',
        target_schema
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION %I.archive_audit_events(INTEGER, INTEGER) TO chenxing_runtime',
        target_schema
    );
END;
$$;
