-- Issue #245: separate the migration/owner role from the runtime role so the
-- append-only audit boundary is enforced by PostgreSQL privileges instead of
-- only by a trigger whose bypass marker any session could set.

-- CREATE ROLE cannot run inside SQLx's default migration transaction.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'chenxing_runtime') THEN
        BEGIN
            CREATE ROLE chenxing_runtime LOGIN;
        EXCEPTION WHEN duplicate_object THEN
            NULL;
        END;
    END IF;
END
$$;

DO $$
DECLARE
    target_schema text := current_schema();
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO chenxing_runtime', target_schema);
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO chenxing_runtime',
        target_schema
    );

    -- The runtime role is not the table owner, so REVOKE is an actual
    -- permission boundary here. Table ownership stays with the migration role.
    EXECUTE format(
        'REVOKE UPDATE, DELETE, TRUNCATE ON %I.audit_events FROM chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'REVOKE UPDATE, DELETE, TRUNCATE ON %I.audit_events_archive FROM chenxing_runtime',
        target_schema
    );
END
$$;

-- The archive function runs with owner privileges but with a fixed search_path,
-- so the runtime role can archive through the supported path without receiving
-- audit DELETE privileges.
DO $$
DECLARE
    target_schema text := current_schema();
BEGIN
    EXECUTE format(
        'ALTER FUNCTION archive_audit_events(INTEGER, INTEGER)
             SECURITY DEFINER
             SET search_path = pg_catalog, %I',
        target_schema
    );
    EXECUTE format(
        'REVOKE ALL ON FUNCTION %I.archive_audit_events(INTEGER, INTEGER) FROM PUBLIC',
        target_schema
    );
    EXECUTE format(
        'GRANT EXECUTE ON FUNCTION %I.archive_audit_events(INTEGER, INTEGER) TO chenxing_runtime',
        target_schema
    );
END
$$;
