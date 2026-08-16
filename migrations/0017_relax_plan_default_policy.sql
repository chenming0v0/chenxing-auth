-- The v1.0.6 release relaxed the requirement that an active default plan must
-- always exist. Migration 0007 was already published with the stricter rule
-- and must stay byte-identical; this migration carries the new policy forward.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE connamespace = current_schema()::regnamespace
          AND conname = 'plans_default_must_be_active'
    ) THEN
        ALTER TABLE plans
            ADD CONSTRAINT plans_default_must_be_active
            CHECK (status = 'active' OR is_default = FALSE);
    END IF;
END
$$;
