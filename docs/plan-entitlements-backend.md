# 后端 Plan：可自定义套餐 / 权益系统

> 目标：把当前硬编码的配额（客户端 2 个、每日 2500、每月 50000）改成**管理员可在后台自由定义的套餐**，每个用户挂一个套餐；再新增**并发（QPS）限制**。用户端有一个只读的「套餐与权益」页，管理端有套餐 CRUD + 给用户分配套餐。

## 0. 与前端的 API 契约（两边必须一致）

这是唯一的对接面。前端已按此实现，后端务必照此返回。

### 用户端（只读）
`GET /api/v1/auth/entitlements` — 需要登录会话

```jsonc
{
  "plan": {
    "code": "vip",              // 套餐机器码
    "name": "VIP",              // 展示名
    "description": "适合重度接入方", // 可空
    "validity": "permanent"     // "permanent" 或 RFC3339 到期时间字符串
  },
  "entitlements": [
    // used=已用；limit=上限，null 表示无限（∞）；limit 省略/undefined 表示"只是个数值、无上限概念"（如 QPS）
    { "key": "oauth_clients", "label": "OAuth 应用数",  "used": 1,    "limit": 2 },
    { "key": "daily_auth",    "label": "每日授权调用",  "used": 0,    "limit": 2500 },
    { "key": "monthly_auth",  "label": "每月授权调用",  "used": 2300, "limit": 50000 },
    { "key": "max_qps",       "label": "最大并发（请求/秒）", "used": 35 }  // 无 limit 字段 → 前端只显示数字，不画进度条
  ]
}
```

约定：
- `entitlements` 是**有序数组**，前端按顺序渲染卡片，后端加新权益项只要往数组里加即可，前端无需改动。
- `used`/`limit` 都是整数。`limit: null` → 前端显示 ∞；无 `limit` 字段 → 只显示数字。

### 管理端（套餐 CRUD，需要 ManageSettings 或新建 ManagePlans 权限）
```
GET    /api/v1/admin/plans                 列出全部套餐（含 archived）
POST   /api/v1/admin/plans                 新建
PUT    /api/v1/admin/plans/{id}            更新
POST   /api/v1/admin/plans/{id}/archive    归档（不物理删除，避免已挂用户悬空）
POST   /api/v1/admin/plans/{id}/restore    取消归档
POST   /api/v1/admin/users/{user_id}/plan  给用户分配套餐 body: { "plan_id": 123, "expires_at": null }
```

套餐对象：
```jsonc
{
  "id": 1,
  "code": "vip",
  "name": "VIP",
  "description": "…",
  "oauth_clients_limit": 2,        // 对应 USER_OAUTH_CLIENT_QUOTA
  "daily_auth_limit": 2500,        // 对应 DAILY_AUTHORIZATION_LIMIT
  "monthly_auth_limit": 50000,     // null = 无限
  "max_qps": 35,                   // null = 不限并发
  "is_default": true,              // 新注册用户 & 未分配用户默认套餐
  "status": "active",              // active | archived
  "assigned_users": 12,            // 该套餐当前挂了多少用户（列表接口可选返回）
  "created_at": "…", "updated_at": "…"
}
```
`monthly_auth_limit`/`max_qps` 为 `null` 语义上就是"无限/不限"，会映射到 `entitlements` 里的 `limit: null` 或省略。

---

## 1. 数据库迁移 `migrations/0002_plans.sql`

参考 `src/db.rs` 的 `embedded_migrator()`：**新增迁移必须在这里注册第 2 条 Migration**，否则不会执行。

```sql
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
```

> 决策：用**固定列**存限额（不是 JSONB），因为限额种类是固定的四项，类型安全、SQL 好写。若以后要支持任意 key 的权益，再加一张 `plan_entitlements(plan_id, key, value)` 附表，不影响现有列。

当前合并迁移链中，sessions lane 使用 `migrations/0006_session_epochs.sql`；计划默认值约束使用后续的 `migrations/0007_plan_default_invariant.sql`。两者的迁移版本必须保持唯一且连续，已应用迁移不得通过复用旧版本号改写 checksum。

## 2. 新模块 `src/plans/`

照 `src/clients/`、`src/oauth/providers/` 的分层写：
- `domain.rs` — `Plan` 结构体、`PlanInput`/`ValidatedPlanInput`、校验（name 非空、code 唯一格式、limit >= 0、default 唯一）、`PlanError`。
- `repository.rs` — `list_plans`、`find_by_id`、`find_default`、`find_for_user(user_id)`（JOIN users.plan_id，取不到就回退 default）、`insert`、`update`、`set_status`、`assign_to_user`。注意 `is_default` 切换要在事务里先清掉旧默认（配合上面的唯一索引，用 `pg_advisory_xact_lock` 或先 `UPDATE plans SET is_default=FALSE`）。
- `service.rs` — `PlanService { pool }`，包住 repository，暴露 `effective_plan_for_user(user_id) -> Plan`（含过期回退：`plan_expires_at` 过了就当默认套餐）。
- 在 `src/lib.rs` 加 `pub mod plans;`。
- 在 `src/state.rs` 的 `AppState` 加 `pub plans: PlanService`，并在 `AppState::new` 里 `PlanService::new(database.clone())` 装配。

## 3. 配额改造（把硬编码换成读套餐）

1. **客户端数量**：`src/clients/repository.rs::insert_owned_client` 里现在写死 `USER_OAUTH_CLIENT_QUOTA`（`src/clients/service.rs:23`）。改成传入 limit 参数——由调用方 `register_for_user` 先查 `plans.effective_plan_for_user`，把 `oauth_clients_limit` 传进来。事务内 `COUNT(*)` 比较不变。
2. **日/月授权**：`src/oauth/quota.rs` 的消费和 `snapshot` 都接收由 `Plan::auth_quota_limits()` 生成的命名限额值。授权入口先根据 Client 的 `owner_user_id` 查 owner 的 effective plan，再把同一份日/月限额传入消费；Client 列表和权益页也从目标 owner/user 的 effective plan 生成同一份限额传给 `snapshot`，因此快照的 used 只来自 Redis，limit 只来自套餐。
   - 注意：Redis 计数目前是**按 client_id**。用户端权益页要按**用户**汇总，需要遍历该用户所有 client 的 snapshot 求和（见 §4）。`monthly_auth_limit = NULL`（无限）时，跳过月度检查、`entitlements` 返回 `limit: null`。
3. **并发 QPS（新增）**：目前无限流。新增 `src/oauth/rate_limit.rs`，Redis 固定窗口/令牌桶（1 秒窗口，key=`chenxing:qps:{client_id}` 或按 user）。在 `/oauth/token` 或 `issue_authorization_code_result` 入口检查，超了返 `error::too_many_requests("qps_exceeded", …)`（helper 已存在于 `src/error.rs:69`）。`max_qps = NULL` 时不启用。

## 4. 用户端 entitlements 汇总 handler

新 `src/users/entitlements_handlers.rs`（照 `users/ui_handlers.rs` 的 `current_user` 模式）：
1. `current_user(&state, &headers)` 拿 user_id。
2. `state.plans.effective_plan_for_user(user_id)` 拿套餐。
3. 组装 `entitlements` 数组：
   - `oauth_clients`：`state.clients.list_all_for_user(user_id).len()` 作 used（分页循环拉全该用户全部 client，见 Issue #415），plan.oauth_clients_limit 作 limit。
   - `daily_auth` / `monthly_auth`：遍历该用户的 client，`oauth_quotas.snapshot(client_id)` 求和 used，plan 的 limit 作 limit。
   - `max_qps`：used = plan.max_qps，无 limit 字段（前端只显示数字）。
4. 在 `src/api.rs` 注册 `GET /api/v1/auth/entitlements`。

## 5. 管理端 handler + 路由

- 新 `src/admin/plan_handlers.rs`：list/create/update/archive/restore/assign，全部走 `current_admin_permission(&state, &headers, AdminPermission::ManageSettings)`（见 `src/admin/ui_handlers.rs` 用法）或新增 `ManagePlans` 权限枚举。
- 在 `src/api.rs` 注册 §0 那批 `/api/v1/admin/plans*` 路由。
- 写操作记 `audit`（照 provider_handlers 的 `state.audit.record(...)`）。

## 6. 测试

- 迁移后种子默认套餐存在、行为与旧硬编码一致（回归）。
- 分配套餐后 client 数量 / 日月配额按新 limit 生效。
- `monthly_auth_limit = NULL` 时不拦月度。
- QPS 限流：1 秒滑动窗口内超过 max_qps 的请求被拒。
- entitlements 接口按用户正确汇总多个 client 的用量。

## 交付顺序建议
迁移 → plans 模块 → state 装配 → entitlements 接口（前端最先要联调这个）→ 配额改造 → QPS → 管理端 CRUD。
