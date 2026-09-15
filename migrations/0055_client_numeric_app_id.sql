-- 数字 App ID：系统分配的全局唯一数字，用于回调路径（/app/<id>/oauth/callback）。
-- 与展示用的 client_name 分离，改名字不需要动 Android 端声明。
--
-- IDENTITY 默认从 1 开始递增。本迁移必须幂等：升级测试会在账本回退到 0046
-- 后重放 0047 之后的全部迁移，列可能已经存在。
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS numeric_app_id BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE;

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS android_asset_link JSONB;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'oauth_clients'::regclass
          AND conname = 'oauth_clients_android_asset_link_object_check'
    ) THEN
        ALTER TABLE oauth_clients
            ADD CONSTRAINT oauth_clients_android_asset_link_object_check
                CHECK (android_asset_link IS NULL OR jsonb_typeof(android_asset_link) = 'object');
    END IF;
END
$$;
