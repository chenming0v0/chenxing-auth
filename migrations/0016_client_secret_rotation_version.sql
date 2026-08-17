-- Issue #190: make Client Secret rotation a compare-and-swap operation.
-- Rollback note: stop the application and roll back the application code first,
-- then drop this column and constraint if a deployment must be reverted.

ALTER TABLE oauth_clients
    ADD COLUMN client_secret_version BIGINT NOT NULL DEFAULT 0;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_client_secret_version_check
    CHECK (client_secret_version >= 0);
