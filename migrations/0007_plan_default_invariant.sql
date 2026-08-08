-- Repair states that could be written before plan mutations were serialized.
UPDATE plans
SET is_default = FALSE
WHERE status = 'archived' AND is_default = TRUE;

UPDATE plans
SET is_default = TRUE
WHERE id = (
    SELECT id
    FROM plans
    WHERE status = 'active'
    ORDER BY created_at, id
    LIMIT 1
)
  AND NOT EXISTS (
      SELECT 1 FROM plans WHERE status = 'active' AND is_default = TRUE
  );

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM plans WHERE status = 'active' AND is_default = TRUE) THEN
        RAISE EXCEPTION 'plans must have an active default plan';
    END IF;
END
$$;

ALTER TABLE plans
    ADD CONSTRAINT plans_default_must_be_active CHECK (status = 'active' OR is_default = FALSE);
