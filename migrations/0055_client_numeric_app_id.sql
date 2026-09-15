-- 数字 App ID：系统分配的全局唯一数字，用于回调路径（/app/<id>/oauth/callback）。
-- 与展示用的 client_name 分离，改名字不需要动 Android 端声明。
--
-- IDENTITY 默认从 1 开始递增，不回填已有行。
ALTER TABLE oauth_clients
    ADD COLUMN numeric_app_id BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE;

ALTER TABLE oauth_clients
    ADD COLUMN android_asset_link JSONB;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_android_asset_link_object_check
        CHECK (android_asset_link IS NULL OR jsonb_typeof(android_asset_link) = 'object');
