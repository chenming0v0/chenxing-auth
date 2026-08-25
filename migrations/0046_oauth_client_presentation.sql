-- RFC 7591 / OIDC Dynamic Client Registration presentation metadata.
--
-- logo_uri and client_uri are optional display fields for the consent screen.
-- The application never fetches these URLs (no SSRF). Missing values do not
-- affect authorization, token exchange, or client authentication.
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   ALTER TABLE oauth_clients
--     DROP COLUMN IF EXISTS logo_uri,
--     DROP COLUMN IF EXISTS client_uri;

ALTER TABLE oauth_clients
    ADD COLUMN logo_uri TEXT,
    ADD COLUMN client_uri TEXT;
