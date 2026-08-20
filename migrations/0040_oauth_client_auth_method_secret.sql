-- Issue #580: oauth_clients.auth_method must match client_secret_hash.
--
-- The application type `ClientCredential` already makes illegal pairs
-- unrepresentable: public clients (`none`) carry no hash, confidential
-- clients (`client_secret_basic` / `client_secret_post`) always carry one.
-- Direct SQL and imports bypass that type. PostgreSQL currently only checks
-- that `auth_method` is one of the three strings (0001). A public client with
-- a leftover hash, or a confidential client with a NULL hash, is a valid row
-- until the next authentication or rotation path trips over it.
--
-- Pairing (must stay in lockstep with ClientAuthMethod / ClientCredential):
--   none                  → client_secret_hash IS NULL
--   client_secret_basic   → client_secret_hash IS NOT NULL
--   client_secret_post    → client_secret_hash IS NOT NULL
--
-- Unknown auth_method values are already rejected by
-- `oauth_clients_auth_method_check`. This CHECK is only the pairing.
--
-- Existing illegal values:
--   We refuse to invent a replacement (dropping a hash, or synthesizing one).
--   The DO block fails the migration and lists offending client_id values so
--   an operator can fix the rows. ADD CONSTRAINT would also fail, but with a
--   generic "violated by some row" message that does not say which row.
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   ALTER TABLE oauth_clients
--     DROP CONSTRAINT IF EXISTS oauth_clients_auth_method_secret_check;

DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(client_id, ', ' ORDER BY client_id)
    INTO offending
    FROM oauth_clients
    WHERE NOT (
        (auth_method = 'none' AND client_secret_hash IS NULL)
        OR (
            auth_method IN ('client_secret_basic', 'client_secret_post')
            AND client_secret_hash IS NOT NULL
        )
    );

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'oauth_clients contain auth_method/client_secret_hash pairs that violate the credential invariant (client_id: %). Fix those rows before this migration; they will not be rewritten automatically.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_auth_method_secret_check
        CHECK (
            (auth_method = 'none' AND client_secret_hash IS NULL)
            OR (
                auth_method IN ('client_secret_basic', 'client_secret_post')
                AND client_secret_hash IS NOT NULL
            )
        );
