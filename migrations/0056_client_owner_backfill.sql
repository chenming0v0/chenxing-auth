-- 存量无主 OAuth Client 回填到第一个未禁用 Owner。
-- 幂等：只更新 owner_user_id IS NULL 的行；系统里还没有 Owner 时整句不改任何行。
UPDATE oauth_clients
SET owner_user_id = (
    SELECT id
    FROM users
    WHERE role = 'owner' AND status <> 'disabled'
    ORDER BY id ASC
    LIMIT 1
)
WHERE owner_user_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM users
      WHERE role = 'owner' AND status <> 'disabled'
  );
