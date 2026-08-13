-- Repair the canonical email unique constraint for databases migrated while
-- multiple schemas were active in parallel.
--
-- Migration 0025 checked pg_constraint by constraint name alone. Constraint
-- names are schema-local, but pg_constraint is database-wide, so a constraint
-- on another schema's users table could make 0025 skip the current table. The
-- column and its NOT NULL invariant were still installed; only uniqueness was
-- missing. Bind the existence check to the users relation resolved through the
-- current search_path, then add the required named constraint when absent.
--
-- Adding the constraint deliberately fails if duplicate canonical values have
-- appeared since 0025. Silently deleting or merging accounts would corrupt
-- ownership of sessions, consents, plans, and audit records.
--
-- This is a repair for a required invariant and must not be rolled back on its
-- own. To roll back the canonical-email feature as a whole, follow the rollback
-- procedure documented in 0025_user_canonical_email.sql.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'users'::regclass
          AND conname = 'users_canonical_email_key'
    ) THEN
        ALTER TABLE users
            ADD CONSTRAINT users_canonical_email_key UNIQUE (canonical_email);
    END IF;
END
$$;
