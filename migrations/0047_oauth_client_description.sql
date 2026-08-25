-- Optional client description for the developer console and consent screen.
-- Display-only; missing values do not affect authorization or token exchange.
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   ALTER TABLE oauth_clients DROP COLUMN IF EXISTS description;

ALTER TABLE oauth_clients
    ADD COLUMN description TEXT;
