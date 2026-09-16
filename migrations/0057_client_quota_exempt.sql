-- quota_exempt：管理面/平台签发的 Client 不占自助额度、不走套餐授权日/月配额与 QPS，
-- 且只有这类 Client 的 Android 声明进入公开 /.well-known/assetlinks.json。
-- owner_user_id 仍表示谁能改这行，不因配额改回 NULL。
--
-- 升级测试会在账本回退到 0046 后重放 0047 之后的迁移，列和触发器可能已经存在。

ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS quota_exempt BOOLEAN NOT NULL DEFAULT false;

-- 当前 ADMIN_TOKEN 落库 actor_type = 'system_token'；产品口径的 admin/system
-- 一并纳入，兼容可能出现过的历史写法。session 管理员与自助创建都写 actor_type='user'，
-- 无法从审计区分，因此不靠 user 审计回填豁免，避免把普通用户自助应用标成豁免。
UPDATE oauth_clients
SET quota_exempt = true
WHERE client_id IN (
    SELECT resource_id
    FROM audit_events
    WHERE action = 'client_create'
      AND resource_type = 'oauth_client'
      AND actor_type IN ('admin', 'system', 'system_token')
      AND resource_id IS NOT NULL
);

-- 0056 把无主历史行 stamp 到第一个未禁用 Owner。那些行往往没有审计（或只有
-- system_token 审计，已由上一句覆盖）。保守条件：当前 owner 是第一个未禁用
-- Owner，且不存在 actor_type=user 的 client_create 审计。有 user 审计的行保持
-- 非豁免——那是自助创建或无法与自助区分的 session 管理创建。
UPDATE oauth_clients AS client
SET quota_exempt = true
WHERE client.quota_exempt = false
  AND client.owner_user_id = (
      SELECT id
      FROM users
      WHERE role = 'owner' AND status <> 'disabled'
      ORDER BY id ASC
      LIMIT 1
  )
  AND NOT EXISTS (
      SELECT 1
      FROM audit_events AS event
      WHERE event.action = 'client_create'
        AND event.resource_type = 'oauth_client'
        AND event.resource_id = client.client_id
        AND event.actor_type = 'user'
  );

-- 删除用户时豁免行不得被 ON DELETE CASCADE 清掉：先把 owner 置空，保留 Client。
-- 非豁免行继续走 FK CASCADE。
CREATE OR REPLACE FUNCTION detach_quota_exempt_clients_on_user_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE oauth_clients
    SET owner_user_id = NULL
    WHERE owner_user_id = OLD.id
      AND quota_exempt;
    RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS detach_quota_exempt_clients_on_user_delete ON users;
CREATE TRIGGER detach_quota_exempt_clients_on_user_delete
    BEFORE DELETE ON users
    FOR EACH ROW
    EXECUTE FUNCTION detach_quota_exempt_clients_on_user_delete();
