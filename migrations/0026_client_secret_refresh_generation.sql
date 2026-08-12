-- Issue #310: preserve pre-upgrade Refresh Tokens while making every future
-- Client Secret rotation a hard generation boundary.
--
-- Existing rows start with the compatibility bit enabled because Refresh Token
-- payloads written by older binaries did not contain client_secret_version.
-- New Clients default to false, and the rotation UPDATE permanently clears the
-- bit while incrementing client_secret_version.
--
-- Deployment note: drain token issuance or upgrade every serving instance
-- before rotating a Secret. Older binaries cannot stamp the generation field.
--
-- Rollback note: deploy code that no longer reads this column before dropping
-- it. Rolling back also removes the ability to distinguish legacy payloads from
-- a stale generation, so drain token endpoints during that rollback.

ALTER TABLE oauth_clients
    ADD COLUMN allow_legacy_refresh_tokens BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE oauth_clients
    ALTER COLUMN allow_legacy_refresh_tokens SET DEFAULT FALSE;
