-- Issue #547: the runtime role may inspect migration state, but only the
-- migration owner may mutate SQLx's ledger. Migration 0019 granted DML on all
-- existing and future tables, which unintentionally included this table.
DO $$
DECLARE
    target_schema text := current_schema();
BEGIN
    EXECUTE format(
        'REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLE %I._sqlx_migrations FROM chenxing_runtime',
        target_schema
    );

    -- Future tables must receive runtime write privileges explicitly. Keeping
    -- SELECT as the only table default prevents a recreated SQLx ledger from
    -- silently inheriting mutation privileges again.
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON TABLES FROM chenxing_runtime',
        target_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT ON TABLES TO chenxing_runtime',
        target_schema
    );
END
$$;
