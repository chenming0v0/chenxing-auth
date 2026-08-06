-- Restore the bootstrap row without taking the default away from an existing plan.
-- If another plan is already the default, basic remains available as a normal plan.
-- This is data-only; any rollback requires reviewing assignments before deleting basic.
INSERT INTO plans (
    code,
    name,
    description,
    oauth_clients_limit,
    daily_auth_limit,
    monthly_auth_limit,
    max_qps,
    is_default,
    status
)
SELECT
    'basic',
    '基础版',
    '默认套餐',
    2,
    2500,
    50000,
    NULL,
    NOT EXISTS (SELECT 1 FROM plans WHERE is_default = TRUE),
    'active'
WHERE NOT EXISTS (SELECT 1 FROM plans WHERE code = 'basic')
ON CONFLICT (code) DO NOTHING;
