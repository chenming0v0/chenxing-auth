-- 为 user_consents 增加软删除标记，将撤销状态从 Redis 迁移至 PostgreSQL 作为权威事实源。
--
-- **背景**（Issue #64）：
-- 撤销同意操作的唯一持久化凭据是 Redis 中的 SET 标记。当 Redis 丢失数据或发生故障转移时，
-- 该标记可能消失，导致已撤销的同意重新生效（撤销失效）。
--
-- **解决方案**：
-- 增加 `revoked_at` 列，将撤销事实持久化至数据库。Redis 标记降级为可失效缓存：
-- - 数据库 `revoked_at IS NOT NULL` 为权威判定
-- - Redis 命中时直接返回缓存结果
-- - Redis 未命中时回源查询数据库，并回填缓存
--
-- **软删除语义**：
-- 保留 `revoked_at` 列而不是删除行，可保存撤销事实以供审计，并支持未来可能的「再次授权」功能。
-- 用户重新授权时，`ConsentService::save` 的 ON CONFLICT 子句会将 `revoked_at` 重置为 NULL。
--
-- **默认值 NULL**：
-- 表示「未撤销」。存量数据自动继承此语义，迁移无需回填数据。
--
-- **兼容性**：
-- 幂等操作：使用 `IF NOT EXISTS` 子句，允许在已执行该迁移的环境中重复运行。

ALTER TABLE user_consents
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;
