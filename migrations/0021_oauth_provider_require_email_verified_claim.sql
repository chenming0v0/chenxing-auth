-- 外部 IdP provider 必须能判断邮箱验证状态（Issue #261）。
--
-- **背景**：
-- `oauth_providers.email_verified_claim` 自 provider 功能上线起就是可空列。
-- 应用层此前的行为是：该列为 NULL 时跳过邮箱验证检查，`ExternalUser.email_verified`
-- 直接落成 false，随后照常解析身份并自动建号。这等于任何人只要在外部 IdP 上
-- 填一个别人的邮箱（很多 IdP 允许未验证邮箱登录），就能在本平台开出一个绑定该
-- 邮箱的账号，后续还可能与本地账号发生邮箱归属冲突。
--
-- **本次改动**：
-- 应用层改成 fail-closed：claim 缺失、类型不是 bool、值为 false 一律拒绝身份解析和
-- 自动建号。数据库这一层给出与之匹配的持久化约束。
--
-- **为什么不是无条件 NOT NULL**：
-- 存量库里可能已有 `email_verified_claim IS NULL` 的行。直接加 NOT NULL 会让迁移在
-- 这些环境里失败，运维只能手工改数据后重跑，属于典型的「迁移把线上升级卡死」。
-- 这里改成两步：
--   1. 把这类 provider 停用（数据仍然保留，管理员能在控制台看到并补齐配置）。
--   2. 只对 status = 'active' 的行要求 claim 非空。
-- 停用行保持原样，迁移在任何存量数据上都能跑通；启用路径由约束 + 应用层共同守住。
--
-- **回滚**：
-- 先回滚应用代码，再 `ALTER TABLE oauth_providers DROP CONSTRAINT
-- oauth_providers_active_requires_email_verified_claim;`。被本迁移停用的 provider
-- 不会自动恢复启用状态，这是有意的：它们的配置确实不足以安全放行外部邮箱。

-- 第 1 步：停用无法判断邮箱验证状态的 provider。
-- 空白串等同缺失：管理端表单和旧脚本都可能写入 ''，把它当成已配置就等于没修。
UPDATE oauth_providers
SET status = 'disabled',
    updated_at = NOW()
WHERE status = 'active'
  AND (email_verified_claim IS NULL OR btrim(email_verified_claim) = '');

-- 第 2 步：启用状态与「claim 可用」绑定成同一个事实。
-- 停用行不受约束，因此存量数据无需清理即可通过迁移。
ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_active_requires_email_verified_claim
    CHECK (
        status <> 'active'
        OR (email_verified_claim IS NOT NULL AND btrim(email_verified_claim) <> '')
    );
