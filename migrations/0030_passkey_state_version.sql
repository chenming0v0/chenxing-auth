ALTER TABLE user_passkeys
    ADD COLUMN state_version BIGINT NOT NULL DEFAULT 1;
