CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_name TEXT NOT NULL,
    client_secret_hash TEXT,
    redirect_uris JSONB NOT NULL DEFAULT '[]'::jsonb,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE user_consents (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
