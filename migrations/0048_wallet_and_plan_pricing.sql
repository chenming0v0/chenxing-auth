-- Internal 辰星点 wallet and self-serve plan pricing.
-- Existing plans keep price_points = 0 (admin-assign only, not self-purchasable).
--
-- Rollback (sqlx Simple migrations have no automatic down):
--   DROP TABLE IF EXISTS wallet_ledger;
--   DROP TABLE IF EXISTS user_wallets;
--   ALTER TABLE plans
--     DROP CONSTRAINT IF EXISTS plans_billing_period_check,
--     DROP CONSTRAINT IF EXISTS plans_price_points_check,
--     DROP COLUMN IF EXISTS billing_period,
--     DROP COLUMN IF EXISTS price_points;

ALTER TABLE plans
  ADD COLUMN price_points BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN billing_period TEXT NOT NULL DEFAULT 'one_time';

ALTER TABLE plans
  ADD CONSTRAINT plans_price_points_check CHECK (price_points >= 0),
  ADD CONSTRAINT plans_billing_period_check CHECK (billing_period IN ('one_time', 'monthly', 'yearly'));

CREATE TABLE user_wallets (
  user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
  balance BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT user_wallets_balance_check CHECK (balance >= 0)
);

CREATE TABLE wallet_ledger (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  amount BIGINT NOT NULL,
  balance_after BIGINT NOT NULL,
  kind TEXT NOT NULL,
  note TEXT,
  reference_type TEXT,
  reference_id TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT wallet_ledger_amount_check CHECK (amount <> 0),
  CONSTRAINT wallet_ledger_balance_after_check CHECK (balance_after >= 0),
  CONSTRAINT wallet_ledger_kind_check CHECK (kind IN ('credit', 'purchase', 'adjust'))
);

CREATE INDEX wallet_ledger_user_created_idx ON wallet_ledger (user_id, created_at DESC, id DESC);

GRANT SELECT, INSERT, UPDATE ON TABLE user_wallets TO chenxing_runtime;
GRANT SELECT, INSERT ON TABLE wallet_ledger TO chenxing_runtime;
GRANT USAGE, SELECT ON SEQUENCE wallet_ledger_id_seq TO chenxing_runtime;
