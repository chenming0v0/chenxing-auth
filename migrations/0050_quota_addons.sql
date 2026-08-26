-- Plan-configured authorization quota add-ons. Purchases are immutable grants
-- for the user's current plan period; there is deliberately no renewal job.
ALTER TABLE users ADD COLUMN plan_entitlement_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE plan_quota_addons (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    plan_id BIGINT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    price_points BIGINT NOT NULL,
    daily_auth_limit BIGINT NOT NULL,
    monthly_auth_limit BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT plan_quota_addons_code_key UNIQUE (plan_id, code),
    CONSTRAINT plan_quota_addons_id_plan_id_key UNIQUE (id, plan_id),
    CONSTRAINT plan_quota_addons_price_check CHECK (price_points > 0),
    CONSTRAINT plan_quota_addons_daily_check CHECK (daily_auth_limit BETWEEN 0 AND 1000000),
    CONSTRAINT plan_quota_addons_monthly_check CHECK (monthly_auth_limit BETWEEN 0 AND 31000000),
    CONSTRAINT plan_quota_addons_status_check CHECK (status IN ('active', 'archived'))
);
CREATE TABLE user_quota_addon_purchases (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    plan_id BIGINT NOT NULL REFERENCES plans(id) ON DELETE RESTRICT,
    addon_id BIGINT NOT NULL REFERENCES plan_quota_addons(id) ON DELETE RESTRICT,
    plan_entitlement_version BIGINT NOT NULL,
    daily_auth_limit BIGINT NOT NULL,
    monthly_auth_limit BIGINT NOT NULL,
    plan_expires_at TIMESTAMPTZ,
    purchased_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_quota_addon_addon_plan_fkey
        FOREIGN KEY (addon_id, plan_id) REFERENCES plan_quota_addons(id, plan_id) ON DELETE RESTRICT,
    CONSTRAINT user_quota_addon_daily_check CHECK (daily_auth_limit >= 0),
    CONSTRAINT user_quota_addon_monthly_check CHECK (monthly_auth_limit >= 0),
    CONSTRAINT user_quota_addon_version_check CHECK (plan_entitlement_version >= 0)
);
CREATE INDEX plan_quota_addons_plan_status_idx ON plan_quota_addons (plan_id, status, id);
CREATE INDEX user_quota_addon_active_idx ON user_quota_addon_purchases (user_id, plan_entitlement_version, plan_expires_at);
GRANT SELECT, INSERT, UPDATE ON TABLE plan_quota_addons TO chenxing_runtime;
GRANT SELECT, INSERT ON TABLE user_quota_addon_purchases TO chenxing_runtime;
GRANT USAGE, SELECT ON SEQUENCE plan_quota_addons_id_seq TO chenxing_runtime;
GRANT USAGE, SELECT ON SEQUENCE user_quota_addon_purchases_id_seq TO chenxing_runtime;
