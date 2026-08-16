-- User avatar storage: keep the normalized avatar bytes on the user row.
--
-- Storage note: the application never stores the uploaded bytes. Every upload is
-- decoded and re-encoded to a 256x256 JPEG (~20 KiB), so the blob stays small
-- enough to live in a TOAST-compressible column instead of requiring an object
-- store or a shared volume for single-binary deployments.
--
-- Rollback note: stop the application and roll back the application code first,
-- then drop the constraint and these columns if a deployment must be reverted.

ALTER TABLE users
    ADD COLUMN avatar_data BYTEA,
    ADD COLUMN avatar_mime TEXT,
    ADD COLUMN avatar_updated_at TIMESTAMPTZ;

-- The three columns describe a single fact. A row holding bytes without a MIME
-- type would force the serving path to guess a Content-Type, and a row without a
-- timestamp would break cache busting, so partial states are rejected outright.
ALTER TABLE users
    ADD CONSTRAINT users_avatar_complete_check
    CHECK (
        (avatar_data IS NULL AND avatar_mime IS NULL AND avatar_updated_at IS NULL)
        OR (avatar_data IS NOT NULL AND avatar_mime IS NOT NULL AND avatar_updated_at IS NOT NULL)
    );
