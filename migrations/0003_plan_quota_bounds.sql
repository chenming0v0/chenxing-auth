-- Issue #459: bound plans.daily_auth_limit / monthly_auth_limit / max_qps.
--
-- Why these numbers (must stay in lockstep with src/plans/domain.rs):
--   daily   1_000_000  = 400× seed 2500. Authorization grants are interactive;
--                        1M/day/client is ~11.5/s sustained, beyond any real SSO.
--                        daily is NOT NULL and has no unlimited sentinel.
--   monthly 31_000_000 = 31 × daily max, so a plan can grant the daily ceiling
--                        every day of a 31-day month. Need more → NULL (unlimited).
--   max_qps 10_000     = 285× the documented example (35). Token-endpoint QPS
--                        per client; 10k is already DDoS-scale for an auth server.
--                        Need more → NULL (unlimited).
--
-- Existing illegal values:
--   Oversized (above the new ceiling):
--     These values effectively disable the quota. The UPDATE below caps them
--     to the new ceiling. This is an intentional, auditable data change, not
--     a silent read-side clamp.
--   Negative daily/monthly, or max_qps IS NOT NULL AND max_qps < 1:
--     We refuse to invent a business value. In particular we will NOT rewrite
--     negatives to 0: 0 is a real "deny all authorizations" quota and would
--     DoS every client on that plan. The DO block fails the migration and
--     lists offending plan codes so an operator can decide.
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   ALTER TABLE plans
--     DROP CONSTRAINT IF EXISTS plans_daily_auth_limit_check,
--     DROP CONSTRAINT IF EXISTS plans_monthly_auth_limit_check,
--     DROP CONSTRAINT IF EXISTS plans_max_qps_check;
--   Capped rows are NOT restored. Snapshot `plans` before migrating if the
--   pre-cap values must be recoverable.

-- Cap oversized values that would disable the quota.
UPDATE plans
SET daily_auth_limit = 1000000
WHERE daily_auth_limit > 1000000;

UPDATE plans
SET monthly_auth_limit = 31000000
WHERE monthly_auth_limit > 31000000;

UPDATE plans
SET max_qps = 10000
WHERE max_qps > 10000;

-- Refuse to invent values for negatives / non-positive QPS.
DO $$
DECLARE
    offending TEXT;
BEGIN
    SELECT string_agg(code, ', ' ORDER BY code)
    INTO offending
    FROM plans
    WHERE daily_auth_limit < 0
       OR monthly_auth_limit < 0
       OR max_qps < 1;

    IF offending IS NOT NULL THEN
        RAISE EXCEPTION
            'plans contain illegal quota values that cannot be rewritten automatically (codes: %). Negative daily/monthly limits and non-positive max_qps must be fixed by an operator before this migration; they will not be clamped to 0.',
            offending
            USING ERRCODE = '23514';
    END IF;
END $$;

ALTER TABLE plans
    ADD CONSTRAINT plans_daily_auth_limit_check
        CHECK (daily_auth_limit >= 0 AND daily_auth_limit <= 1000000),
    ADD CONSTRAINT plans_monthly_auth_limit_check
        CHECK (monthly_auth_limit IS NULL
               OR (monthly_auth_limit >= 0 AND monthly_auth_limit <= 31000000)),
    ADD CONSTRAINT plans_max_qps_check
        CHECK (max_qps IS NULL
               OR (max_qps >= 1 AND max_qps <= 10000));
