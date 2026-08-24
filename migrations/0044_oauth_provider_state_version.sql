ALTER TABLE oauth_providers
    ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'oauth_providers'::regclass
          AND conname = 'oauth_providers_state_version_nonnegative'
    ) THEN
        ALTER TABLE oauth_providers
            ADD CONSTRAINT oauth_providers_state_version_nonnegative
            CHECK (state_version >= 1);
    END IF;
END
$$;
