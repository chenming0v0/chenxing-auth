# 统一用户身份与数据库基线重构设计

## 目标

将普通用户、管理员和 Owner 统一为同一个 `users` 身份体系。所有真人身份只拥有一个从 `1` 开始递增的 `BIGINT` 用户 ID；管理员能力由 `users.role` 决定，不再维护独立的管理员账号、密码、Session 或 CSRF 体系。

本仓库仍处于开发阶段，现有 PostgreSQL 和 Redis 数据允许清空。本次重构采用新的干净数据库基线，不提供旧 `admins` 数据到新 `users` 数据的在线迁移，也不保留旧 UUID 主键兼容列。

## 身份模型

`users` 是唯一的人类身份表：

- `id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY`，从 `1` 开始递增。
- `username`、`email` 分别全局唯一，写入前统一规范化为小写。
- `role` 是单值层级角色：`user`、`admin`、`owner`。
- 权限继承关系为 `owner > admin > user`。
- `status` 控制整个账号，包括普通登录、管理访问、OAuth 授权和 UserInfo。
- 密码、TOTP、Passkey、外部 OAuth 身份、资料和 Session 均绑定同一个 `users.id`。

角色权限：

| 能力 | user | admin | owner |
| --- | --- | --- | --- |
| 普通登录、资料、Session、TOTP、Passkey | 是 | 是 | 是 |
| 创建和管理本人 OAuth Client | 是 | 是 | 是 |
| 查看和管理全局用户 | 否 | 是 | 是 |
| 查看和管理全局 OAuth Client | 否 | 是 | 是 |
| 查看审计 | 否 | 是 | 是 |
| 管理应用设置和外部身份提供商 | 否 | 是 | 是 |
| 轮换平台签名密钥 | 否 | 否 | 是 |
| 修改其他用户角色 | 否 | 否 | 是 |

系统必须始终保留至少一个 `active owner`。禁止禁用或降级最后一个活跃 Owner。用户不能修改自己的角色；Owner 通过受保护的管理接口修改其他用户角色。

## 首次初始化

`GET /api/v1/admin/bootstrap/status` 根据是否存在 `role = 'owner'` 的用户返回初始化状态。

`POST /api/v1/admin/bootstrap` 接收：

```json
{
  "username": "chenxing-owner",
  "email": "owner@example.com",
  "password": "at-least-10-chars"
}
```

初始化规则：

- 仅当数据库不存在任何 Owner 时公开可用。
- PostgreSQL advisory transaction lock 保证并发请求最多成功一次。
- 邮箱必须格式合法并全局唯一，但不要求发送验证邮件。
- 创建完整的 `users` 记录，角色固定为 `owner`，ID 在空库中固定为 `1`。
- 初始化成功后不自动创建 Session，用户使用统一登录接口登录。
- SMTP 和邮件发送能力由 Owner 登录后配置，初始化不依赖 SMTP。

## 目标数据库结构

### users

```sql
CREATE TABLE users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    password_login_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    last_login_at TIMESTAMPTZ,
    CONSTRAINT users_role_check CHECK (role IN ('user', 'admin', 'owner')),
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled'))
);
```

### 用户安全数据

- `user_totp_factors.user_id` 是一对一主键和外键。
- `user_passkeys.id` 使用递增 `BIGINT` 主键，`user_id` 引用 `users.id`。
- `oauth_external_identities.id` 使用递增 `BIGINT` 主键，`user_id` 引用 `users.id`。
- 所有用户外键使用统一名称 `user_id` 或表达所有权的 `owner_user_id`，类型均为 `BIGINT`。

### Session

数据库主键和浏览器凭据分离：

- `user_sessions.id BIGINT IDENTITY` 只是内部数据库主键。
- 浏览器 Cookie 使用至少 256 位随机 Session Token。
- PostgreSQL 只保存 Token 的 SHA-256 哈希，不保存 Cookie 明文。
- Redis 使用 Token 哈希作为键并保存短期 Session 载荷。
- `user_sessions.user_id` 引用 `users.id`，用于列举、撤销和审计。
- 管理接口复用同一 Session Cookie 和 CSRF Cookie，不再使用管理员专用 Cookie。

### OAuth 与业务实体

- `oauth_clients.id BIGINT IDENTITY`，公开 `client_id` 继续使用不可预测随机字符串。
- `oauth_clients.owner_user_id BIGINT REFERENCES users(id) ON DELETE CASCADE`。
- `user_consents` 使用 `(user_id, client_id)` 复合主键。
- `oauth_providers.id BIGINT IDENTITY`。
- `oauth_external_identities` 对 `(provider_id, subject)` 和 `(provider_id, user_id)` 保持唯一。
- OAuth 授权码、Refresh Token、State、Nonce、PKCE 和 Client Secret 继续使用随机安全值，不能改为数据库递增 ID。

### 审计和设置

- `audit_events.id BIGINT IDENTITY`。
- `actor_user_id BIGINT NULL REFERENCES users(id) ON DELETE SET NULL` 表示真人操作方。
- Bearer `ADMIN_TOKEN` 自动化操作没有用户 ID，使用 `actor_type = 'system_token'` 和空 `actor_user_id`。
- `resource_type` 与 `resource_id` 保留通用文本形式，避免审计表依赖每一种业务表。
- `app_settings.setting_key` 保留自然主键；配置键不是实体 ID，不强行改成用户 ID。

## 应用层重构

删除独立管理员身份模块中的账号职责：

- 删除 `AdminId`、`AdminService`、管理员仓储和 `AdminSessionStore`。
- 保留管理 HTTP 模块，但其认证上下文改为 `CurrentUser { user_id, role }`。
- 普通接口和管理接口从同一个 Session 中解析用户，并从 PostgreSQL 重新读取当前 `status` 和 `role`，防止角色变更后旧 Session 继续拥有旧权限。
- 管理写操作复用普通 Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 三者绑定。
- `ADMIN_TOKEN` 保留为可选的自动化兼容凭据；为空时拒绝 Bearer 管理访问，但不影响用户 Session 管理访问。

统一登录接口负责所有角色。现有管理员登录接口和管理员专用 Session API 从公开契约中删除；管理前端调用普通登录和登录状态接口，只有 `admin` 或 `owner` 可以进入管理路由。

## 数据库基线策略

由于用户确认现有数据可清空：

1. 将现有 `0001` 到 `0012` 开发迁移压缩为一个新的统一基线迁移。
2. 删除 `legacy_uuid`、`admins` 和所有管理员专用数据结构。
3. 清空本地 PostgreSQL 与 Redis 数据卷后执行新基线。
4. 应用启动仍不得静默修改生产结构；部署脚本必须显式运行迁移。
5. 文档明确本次版本不支持在保留旧数据的情况下滚动升级。

## 并发与一致性

- Owner 初始化在一个事务中持有 advisory lock，检查 Owner 不存在后插入用户。
- 修改角色或状态时锁定目标用户，并在降级/禁用 Owner 前锁定活跃 Owner 集合，保证至少保留一个活跃 Owner。
- 用户创建 OAuth Client 时继续锁定用户行后计算配额，避免并发越限。
- Session 写 PostgreSQL 和 Redis 不是分布式事务：创建失败时执行补偿删除；查找时任何一侧失效都视为 Session 无效。
- 授权码和 Refresh Token 继续使用 Redis 原子消费脚本，错误绑定请求不得烧掉有效凭据。

## API 与前端变化

- Bootstrap 请求新增必填 `email`。
- Bootstrap 响应中的 `id` 是统一用户 ID。
- 登录状态和当前用户响应新增 `role`。
- 管理员列表改为按角色筛选用户的管理接口，返回用户邮箱和统一 ID。
- Owner 从管理后台创建特权账号时必须创建完整用户，提交 `username`、`email`、`password` 和 `role`；角色只允许 `admin` 或 `owner`。
- 新增 Owner 专用角色修改接口。
- 删除管理员专用登录、登出、Session Cookie 和 CSRF Security Scheme。
- 管理控制台与普通控制台共享登录状态；角色决定可见导航和路由访问。
- `openapi.yaml`、`API.md`、前端 TypeScript 类型和 Apifox 导入契约同步更新。

## 测试与验收

- 新空库执行基线后，首个用户和首个 Owner ID 为 `1`。
- 所有实体内部主键按表独立递增，所有用户引用均为 `BIGINT` 外键。
- 并发初始化最多创建一个 Owner。
- `user`、`admin`、`owner` 权限矩阵逐项覆盖。
- Admin 和 Owner 可以正常使用普通用户功能。
- 禁止禁用或降级最后一个活跃 Owner。
- 角色或状态变更立即影响已有 Session 的管理权限。
- Session Cookie 不包含递增数据库 ID，数据库不保存 Cookie 明文。
- PostgreSQL 和 Redis 使用真实容器执行集成测试。
- 完成 Rust、前端、OpenAPI、部署文件、覆盖率、安全审计和 `src-line-limit` 验证。
