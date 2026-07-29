CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY,
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

ALTER TABLE users
    ADD COLUMN password_login_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX oauth_providers_status_idx ON oauth_providers (status);

CREATE TABLE oauth_external_identities (
    id UUID PRIMARY KEY,
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    email TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (provider_id, subject),
    UNIQUE (provider_id, user_id)
);

CREATE INDEX oauth_external_identities_user_idx ON oauth_external_identities (user_id);
