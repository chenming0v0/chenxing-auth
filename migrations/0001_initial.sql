CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    password_login_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'owner')),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled'))
);

CREATE INDEX users_status_idx ON users (status);
CREATE INDEX users_role_idx ON users (role);

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
    CONSTRAINT oauth_clients_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_clients_auth_method_check CHECK (auth_method IN ('client_secret_basic', 'client_secret_post', 'none'))
);

CREATE INDEX oauth_clients_owner_user_id_idx ON oauth_clients (owner_user_id, created_at DESC);

CREATE TABLE user_consents (
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id BIGINT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

CREATE TABLE user_sessions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    token_hash BYTEA NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX user_sessions_user_created_idx ON user_sessions (user_id, created_at DESC);

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

CREATE INDEX user_passkeys_user_idx ON user_passkeys (user_id, created_at DESC);

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
    CONSTRAINT oauth_providers_status_check CHECK (status IN ('active', 'disabled')),
    CONSTRAINT oauth_providers_client_auth_check CHECK (client_auth_method IN ('basic', 'request_body'))
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

CREATE INDEX oauth_external_identities_user_idx ON oauth_external_identities (user_id);

CREATE TABLE audit_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at DESC);
CREATE INDEX audit_events_resource_idx ON audit_events (resource_type, resource_id);
CREATE INDEX audit_events_actor_user_idx ON audit_events (actor_user_id, created_at DESC);

CREATE TABLE app_settings (
    setting_key TEXT PRIMARY KEY,
    setting_value TEXT,
    updated_at TIMESTAMPTZ NOT NULL
);

INSERT INTO app_settings (setting_key, setting_value, updated_at)
VALUES ('registration_email_from', NULL, NOW());
