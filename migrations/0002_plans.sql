CREATE TABLE plans (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    oauth_clients_limit INTEGER NOT NULL DEFAULT 2,
    daily_auth_limit BIGINT NOT NULL DEFAULT 2500,
    monthly_auth_limit BIGINT,          -- NULL = 无限
    max_qps INTEGER,                    -- NULL = 不限
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT plans_status_check CHECK (status IN ('active', 'archived'))
);

-- 只允许一个默认套餐
CREATE UNIQUE INDEX plans_single_default_idx ON plans (is_default) WHERE is_default = TRUE;

ALTER TABLE users
    ADD COLUMN plan_id BIGINT REFERENCES plans(id) ON DELETE SET NULL,
    ADD COLUMN plan_expires_at TIMESTAMPTZ;   -- NULL = 永久有效

-- 种子：把现在的硬编码值作为默认「基础版」，保证迁移后行为不变
INSERT INTO plans (code, name, description, oauth_clients_limit, daily_auth_limit, monthly_auth_limit, max_qps, is_default, status)
VALUES ('basic', '基础版', '默认套餐', 2, 2500, 50000, NULL, TRUE, 'active');
