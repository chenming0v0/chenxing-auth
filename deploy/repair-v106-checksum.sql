-- Compatibility repair for the v1.0.6 release that changed already published
-- migration bytes. Run this as the migration/owner role against the target
-- database before starting the fixed binary.
--
-- It only recognizes the exact v1.0.6 checksums for migrations 2, 7, and 9,
-- validates the schema/data those migrations are expected to have produced,
-- and then rewrites the SQLx metadata to the immutable v1.0.5 baseline. Any
-- unknown checksum or missing invariant aborts without modifying anything.

DO $$
DECLARE
    migration_2_checksum bytea;
    migration_7_checksum bytea;
    migration_9_checksum bytea;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_class
        WHERE relnamespace = current_schema()::regnamespace
          AND relname = '_sqlx_migrations'
    ) THEN
        RAISE NOTICE 'No SQLx migration metadata found; repair is not needed.';
        RETURN;
    END IF;

    SELECT checksum INTO migration_2_checksum
    FROM _sqlx_migrations
    WHERE version = 2;
    IF migration_2_checksum IS NULL THEN
        RAISE EXCEPTION 'Migration 2 is not recorded; refusing checksum repair.';
    ELSIF migration_2_checksum = decode('905eb5742a484721b6de0787517ba12d7673300879e7565df77d134d3f227cf02d093c8547ca568b5387b5ce44046dff', 'hex') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_class
            WHERE relnamespace = current_schema()::regnamespace
              AND relname IN ('plans', 'users')
        )
        OR NOT EXISTS (
            SELECT 1
            FROM pg_indexes
            WHERE schemaname = current_schema()
              AND indexname = 'plans_single_default_idx'
        )
        OR NOT EXISTS (SELECT 1 FROM plans WHERE code = 'basic') THEN
            RAISE EXCEPTION 'Migration 2 repair aborted: plans/users schema or basic seed is missing.';
        END IF;
        UPDATE _sqlx_migrations
        SET checksum = decode('714a0ae3cfa29909ebe32dde11396f378bf7ad546adc2d4f19e2aec23e7040fe6ab9ac0aa50df2e66ddb9a633333cc8c', 'hex')
        WHERE version = 2;
        RAISE NOTICE 'Repaired migration 2 checksum to the immutable v1.0.5 baseline.';
    ELSIF migration_2_checksum = decode('714a0ae3cfa29909ebe32dde11396f378bf7ad546adc2d4f19e2aec23e7040fe6ab9ac0aa50df2e66ddb9a633333cc8c', 'hex') THEN
        RAISE NOTICE 'Migration 2 already matches the immutable baseline.';
    ELSE
        RAISE EXCEPTION 'Migration 2 has an unexpected checksum; refusing automatic repair.';
    END IF;

    SELECT checksum INTO migration_7_checksum
    FROM _sqlx_migrations
    WHERE version = 7;
    IF migration_7_checksum IS NULL THEN
        RAISE EXCEPTION 'Migration 7 is not recorded; refusing checksum repair.';
    ELSIF migration_7_checksum = decode('1f933d63b4a21e89dc59389854fddf9650ed43044232b8a51ba20007ea35790a3578a43be0ef0c373e1b0959ca2a3125', 'hex') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE connamespace = current_schema()::regnamespace
              AND conname = 'plans_default_must_be_active'
        ) THEN
            RAISE EXCEPTION 'Migration 7 repair aborted: plans_default_must_be_active constraint is missing.';
        END IF;
        UPDATE _sqlx_migrations
        SET checksum = decode('f29a20be2d62a3d13429d4ed1ba461b0ecfa7699a5118cc8be80bed57b4de4701434f661d20ed5388dad203e69a15cb8', 'hex')
        WHERE version = 7;
        RAISE NOTICE 'Repaired migration 7 checksum to the immutable v1.0.5 baseline.';
    ELSIF migration_7_checksum = decode('f29a20be2d62a3d13429d4ed1ba461b0ecfa7699a5118cc8be80bed57b4de4701434f661d20ed5388dad203e69a15cb8', 'hex') THEN
        RAISE NOTICE 'Migration 7 already matches the immutable baseline.';
    ELSE
        RAISE EXCEPTION 'Migration 7 has an unexpected checksum; refusing automatic repair.';
    END IF;

    SELECT checksum INTO migration_9_checksum
    FROM _sqlx_migrations
    WHERE version = 9;
    IF migration_9_checksum IS NULL THEN
        RAISE EXCEPTION 'Migration 9 is not recorded; refusing checksum repair.';
    ELSIF migration_9_checksum = decode('fb00009e4b2ada4a3833432a168e5d2273e0726de59c4b49f8d8ab00078d136f22fc9cc70495299e305f5f8423c7f343', 'hex') THEN
        IF NOT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = current_schema()
              AND table_name = 'app_settings'
        )
        OR NOT EXISTS (
            SELECT 1 FROM app_settings WHERE setting_key = 'security_limits'
        ) THEN
            RAISE EXCEPTION 'Migration 9 repair aborted: app_settings or security_limits seed is missing.';
        END IF;
        UPDATE _sqlx_migrations
        SET checksum = decode('6092ab9b2112079914a64f3e3951cd31230ff5f53a2b414169e2ca0e18ed36bf81a433f8a019e176116fdfde3b56d4c4', 'hex')
        WHERE version = 9;
        RAISE NOTICE 'Repaired migration 9 checksum to the immutable v1.0.5 baseline.';
    ELSIF migration_9_checksum = decode('6092ab9b2112079914a64f3e3951cd31230ff5f53a2b414169e2ca0e18ed36bf81a433f8a019e176116fdfde3b56d4c4', 'hex') THEN
        RAISE NOTICE 'Migration 9 already matches the immutable baseline.';
    ELSE
        RAISE EXCEPTION 'Migration 9 has an unexpected checksum; refusing automatic repair.';
    END IF;
END
$$;
