ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_owner_user_id_fkey,
    ADD CONSTRAINT oauth_clients_owner_user_id_fkey
        FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE;
