-- Issue #191: accelerate the existing substring searches without changing their
-- matching semantics. `pg_trgm` supports both LIKE and ILIKE, including patterns
-- with a leading wildcard; patterns shorter than three characters remain correct
-- but may not be indexable.
--
-- Keep the extension in the shared `public` schema so per-test and tenant schemas
-- can use the same operator class. The indexes themselves belong to the current
-- application schema.
--
-- Rollback note: stop the application, drop `users_admin_search_trgm_idx` and
-- `oauth_clients_admin_search_trgm_idx`, then remove this migration record only
-- through the normal migration rollback procedure. Do not drop `pg_trgm` unless
-- this migration installed it and no other schema or index still depends on it.

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE INDEX users_admin_search_trgm_idx
    ON users USING GIN (
        username public.gin_trgm_ops,
        email public.gin_trgm_ops,
        display_name public.gin_trgm_ops
    );

CREATE INDEX oauth_clients_admin_search_trgm_idx
    ON oauth_clients USING GIN (
        client_id public.gin_trgm_ops,
        client_name public.gin_trgm_ops
    );
