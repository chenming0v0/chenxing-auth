ALTER TABLE oauth_clients
    ADD COLUMN owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX oauth_clients_owner_user_id_idx
    ON oauth_clients (owner_user_id, created_at DESC);
