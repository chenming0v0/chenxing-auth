ALTER TABLE oauth_providers
    ADD COLUMN state_version BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT oauth_providers_state_version_nonnegative CHECK (state_version >= 1);
