-- Issue #582: JSONB OAuth/consent/passkey columns must match repository decode.
--
-- Repositories deserialize these columns as `Vec<String>` or a Passkey object.
-- JSONB itself accepts any JSON value, so a maintenance write or import of an
-- object, scalar, or mixed-type array stays in the row and later turns a
-- routine read into a decode error. The row still "exists"; it just cannot
-- be loaded.
--
-- Minimum shapes (must stay in lockstep with the readers):
--   oauth_clients.redirect_uris / scopes  → JSON array of strings
--   user_consents.scopes                  → JSON array of strings
--   oauth_providers.scopes                → JSON array of strings
--   user_passkeys.credential              → JSON object
--
-- String-array CHECKs use `jsonb_path_exists` because PostgreSQL forbids
-- subqueries in CHECK. The path `$[*] ? (@.type() != "string")` is true iff
-- any element is not a JSON string (number, object, null, nested array).
-- Empty arrays (`[]`, the column default) have no matching elements and pass.
--
-- Passkey `credential` is only required to be an object. The inner WebAuthn
-- envelope is owned by webauthn-rs and must not be duplicated in SQL; test
-- fixtures also persist `'{}'::jsonb` as a "factor exists" stub.
--
-- Existing illegal values:
--   We refuse to invent a replacement shape. The DO blocks fail the migration
--   and list offending identifiers so an operator can fix the rows. ADD
--   CONSTRAINT would also fail, but with a generic "violated by some row"
--   message that does not say which row.
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   ALTER TABLE oauth_clients
--     DROP CONSTRAINT IF EXISTS oauth_clients_redirect_uris_check,
--     DROP CONSTRAINT IF EXISTS oauth_clients_scopes_check;
--   ALTER TABLE user_consents
--     DROP CONSTRAINT IF EXISTS user_consents_scopes_check;
--   ALTER TABLE oauth_providers
--     DROP CONSTRAINT IF EXISTS oauth_providers_scopes_check;
--   ALTER TABLE user_passkeys
--     DROP CONSTRAINT IF EXISTS user_passkeys_credential_check;

DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(client_id, ', ' ORDER BY client_id)
    INTO offending
    FROM oauth_clients
    WHERE jsonb_typeof(redirect_uris) <> 'array'
       OR jsonb_path_exists(redirect_uris, '$[*] ? (@.type() != "string")')
       OR jsonb_typeof(scopes) <> 'array'
       OR jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")');

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'oauth_clients contain JSONB values that cannot be decoded as string arrays (client_id: %). Fix those rows before this migration; they will not be rewritten automatically.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(user_id::text || '/' || client_id::text, ', ' ORDER BY user_id, client_id)
    INTO offending
    FROM user_consents
    WHERE jsonb_typeof(scopes) <> 'array'
       OR jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")');

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'user_consents contain JSONB values that cannot be decoded as string arrays (user_id/client_id: %). Fix those rows before this migration; they will not be rewritten automatically.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(slug, ', ' ORDER BY slug)
    INTO offending
    FROM oauth_providers
    WHERE jsonb_typeof(scopes) <> 'array'
       OR jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")');

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'oauth_providers contain JSONB values that cannot be decoded as string arrays (slug: %). Fix those rows before this migration; they will not be rewritten automatically.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(id::text, ', ' ORDER BY id)
    INTO offending
    FROM user_passkeys
    WHERE jsonb_typeof(credential) <> 'object';

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'user_passkeys contain JSONB values that cannot be decoded as a credential object (id: %). Fix those rows before this migration; they will not be rewritten automatically.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_redirect_uris_check
        CHECK (
            jsonb_typeof(redirect_uris) = 'array'
            AND NOT jsonb_path_exists(redirect_uris, '$[*] ? (@.type() != "string")')
        ),
    ADD CONSTRAINT oauth_clients_scopes_check
        CHECK (
            jsonb_typeof(scopes) = 'array'
            AND NOT jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")')
        );

ALTER TABLE user_consents
    ADD CONSTRAINT user_consents_scopes_check
        CHECK (
            jsonb_typeof(scopes) = 'array'
            AND NOT jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")')
        );

ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_scopes_check
        CHECK (
            jsonb_typeof(scopes) = 'array'
            AND NOT jsonb_path_exists(scopes, '$[*] ? (@.type() != "string")')
        );

ALTER TABLE user_passkeys
    ADD CONSTRAINT user_passkeys_credential_check
        CHECK (jsonb_typeof(credential) = 'object');
