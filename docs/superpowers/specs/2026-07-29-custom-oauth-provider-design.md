# 自定义 OAuth/OIDC 提供商设计

## 目标

在辰星认证中枢中增加配置驱动的外部 OAuth 2.0/OIDC 登录能力。管理员可以在设置界面创建、查看、修改和启停任意符合标准授权码流程的外部提供商；用户可以从辰星通行证登录页选择已启用的提供商，通过外部身份注册或登录辰星账号，并继续原有的 OAuth 授权流程。

## 范围与约束

- 支持 OAuth 2.0 Authorization Code 流程和 OIDC UserInfo 风格的 JSON 用户信息接口。
- 不为 GitHub、GitLab、Keycloak 等厂商写死分支；授权地址、Token 地址、UserInfo 地址、Scope、Claim 路径和 Client 认证方式均由提供商配置决定。
- UserInfo 至少必须提供非空 subject 和合法 email；name 可选。Claim 路径使用点分隔 JSON 对象路径，默认值为 `sub`、`email`、`name`。
- 每个外部身份以 `(provider_id, subject)` 唯一绑定本地用户。首次登录只在本地邮箱不存在时创建本地账号；若邮箱已被本地账号占用，拒绝自动绑定，要求未来通过已认证的账号设置流程显式绑定。
- 外部账号不设置可登录的本地密码，使用随机生成的不可用 Argon2 哈希占位；后续只能通过已绑定的外部身份登录，除非未来增加密码设置流程。
- OAuth state 同时保存于 Redis（TTL 10 分钟、单次消费）和 HttpOnly SameSite=Lax Cookie，防止响应注入和登录 CSRF。
- Client Secret 使用 `KEY_DIRECTORY/oauth-provider-secret.key` 中的独立 AES-256-GCM 密钥加密后保存。该密钥随运行时密钥目录保护，不通过 API、页面、日志或审计返回。
- 外部 Token/UserInfo HTTP 请求使用固定超时、只允许 `http`/`https` 配置地址且禁用自动重定向。管理端对端点拥有配置权限，生产部署仍应使用 HTTPS。

## 数据模型

新增迁移 `0004_external_oauth.sql`：

### `oauth_providers`

保存提供商配置：`id`、`name`、`slug`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`client_id`、加密后的 `client_secret_ciphertext`、scope 数组、subject/email/name/email_verified Claim 路径、Client 认证方式、status、创建和更新时间。`slug` 唯一且限制为小写 ASCII 字母、数字、`_`、`-`，长度 1-64。

### `oauth_external_identities`

保存 `(provider_id, subject)` 到 `user_id` 的绑定，并记录最近一次外部 email。对 provider 和 subject 建唯一约束，对 user/provider 建唯一约束，删除提供商或用户时级联删除。

## 端点与页面

### 管理 API

- `POST /api/v1/admin/oauth/providers`：创建提供商。要求 `ManageIdentityProviders` 权限和管理员 CSRF；只返回公开摘要，不返回 Secret。
- `GET /api/v1/admin/oauth/providers`：列出摘要，包括回调地址和 `client_secret_configured`。
- `PUT /api/v1/admin/oauth/providers/{slug}`：更新配置；Secret 为空时保留原值。
- `POST /api/v1/admin/oauth/providers/{slug}/disable`、`/enable`：启停提供商。

所有写操作使用独立管理员 Session 的 `chenxing_admin_csrf` Cookie 与 `X-CSRF-Token` 双提交校验；管理员 Bearer Token 继续作为开发和自动化兼容方式。

### 管理页面

- `GET /admin/settings/oauth`：受管理员权限保护，服务端渲染提供商列表、每个提供商的回调地址和新增/编辑表单。
- 表单使用同页面的管理员 CSRF 值通过 `fetch` 设置 `X-CSRF-Token` 调用管理 API；页面不显示 Secret 原值。
- 管理后台首页增加“OAuth 提供商设置”入口。

### 用户流程

- `GET /auth/login`：保留邮箱密码登录，并动态显示启用的外部提供商按钮。带 `request_id` 时将其带入外部流程。
- `GET /auth/external/{slug}`：校验提供商状态，生成 state，保存 Redis 状态并设置 state Cookie，重定向到提供商授权地址。
- `GET /auth/external/{slug}/callback`：校验 Cookie/Redis state，交换授权码，调用 UserInfo，解析 Claim，查找或创建外部身份，创建辰星 Session。带原始 `request_id` 时跳转授权确认页；否则返回登录页并显示成功状态。

回调失败只返回通用错误页面，不泄露外部响应正文、Token、Client Secret 或内部地址。

## 服务边界

- `src/oauth/providers/domain.rs`：配置验证、Claim 路径、摘要和外部用户信息领域类型。
- `src/oauth/providers/repository.rs`：Provider 和 identity 的 PostgreSQL 读写。
- `src/oauth/providers/state_store.rs`：Redis state 单次存储与消费。
- `src/oauth/providers/secrets.rs`：AES-256-GCM 密钥加载、生成、加解密。
- `src/oauth/providers/service.rs`：管理用例、外部 HTTP token/userinfo 调用、外部身份事务性注册/绑定。
- `src/oauth/providers/handlers.rs`：管理 API、发起登录和回调的 Axum 适配。

`AppState` 持有可 Clone 的 `ExternalOAuthService`，所有路由共享同一密钥管理和 HTTP 配置。领域服务不接收 Axum 请求对象。

## 错误处理与审计

- 配置校验失败返回 `invalid_oauth_provider`。
- 重复 slug 返回 `oauth_provider_conflict`。
- 未启用或不存在的提供商返回 `oauth_provider_not_found`。
- state 不匹配、过期或重放返回通用 `oauth_login_failed` 页面。
- 外部邮箱已存在于本地账号返回通用 `oauth_account_link_required` 页面，不自动合并。
- 创建、更新、启停提供商记录 admin 审计；外部登录成功/失败只记录 provider slug、结果和本地 user id，不记录 code、state、token 或外部用户完整资料。

## 测试策略

- 领域单元测试：slug/URL/Scope/Claim 路径/Client 认证方式校验、Claim 提取和 state Cookie 绑定。
- Redis/数据库集成测试：state 单次消费、提供商 secret 不可逆明文读取、Provider CRUD、外部身份唯一性和事务性首次注册。
- HTTP 集成测试：管理员权限/CSRF、列表脱敏、登录跳转、缺失/错误/重放 state、外部 token/userinfo 失败、首次注册、重复登录、邮箱冲突。
- 为外部 HTTP 增加可注入客户端或本地测试服务器，测试不依赖真实第三方。
- 同步 `openapi.yaml`、`API.md`、README 状态说明，并运行 OpenAPI 校验、Rust 全量检查、覆盖率门槛、审计和 `src-line-limit`。
