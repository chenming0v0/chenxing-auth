# 辰星认证中枢 API

本文档以当前后端代码实际暴露的接口为准，供前端和 OAuth/OIDC 接入方使用。

## 基础约定

- Base URL 使用部署后的认证服务地址，例如 `https://auth.example.com`。
- JSON 请求发送 `Content-Type: application/json`；OAuth Token 和 Revocation 请求发送 `application/x-www-form-urlencoded`。
- 时间使用 RFC 3339 字符串；普通用户和管理员 ID 是从 1 开始递增的整数，Session、OAuth Client 等其他实体 ID 仍使用 UUID 字符串。
- 认证失败、参数错误等 JSON 错误统一为：

```json
{"code":"invalid_credentials","message":"email or password is incorrect"}
```

- 常见状态码：`200` 成功，`201` 创建成功，`204` 成功且无响应体，`400` 参数或业务校验失败，`401` 未认证，`403` 无权限，`409` 冲突，`500` 服务端错误。
- 不要在前端日志中记录密码、Client Secret、Session、授权码或 Token。

## 健康和 OIDC 元数据

### `GET /health`

响应：

```json
{"status":"ok","service":"chenxing-auth"}
```

### `GET /.well-known/openid-configuration`

返回 OIDC Discovery 文档。前端/接入方应优先读取该文档，不要硬编码协议端点。当前至少包含 `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`jwks_uri`、`revocation_endpoint` 等标准字段。

### `GET /.well-known/jwks.json`

返回当前及验证过渡期公钥集合。只用于验证 JWT，不包含私钥。

## 用户和浏览器 Session

### `POST /api/v1/users`

创建辰星通行证账号。

请求：

```json
{"username":"chenxing-user","email":"user@example.com","password":"at-least-10-chars","display_name":"显示名称"}
```

`username` 必填，长度 3-64 个字符且不可包含空格或 `@`；必须唯一。`display_name` 可省略或为 `null`，最长 128 个字符；密码至少 10 个字符。

响应 `201`：

```json
{"user":{"id":1,"username":"chenxing-user","email":"user@example.com","display_name":"显示名称","status":"active","created_at":"2026-07-28T00:00:00Z"}}
```

常见错误：`invalid_username`、`invalid_email`、`password_too_short`、`display_name_too_long`、`username_already_registered`、`email_already_registered`。

### `POST /api/v1/auth/login`

请求：

```json
{"identifier":"chenxing-user","password":"at-least-10-chars","totp_code":"123456"}
```

`identifier` 可以填写普通用户注册时的 `username` 或邮箱地址。为兼容旧客户端，服务端仍接受请求体中的 `email` 别名；新客户端应使用 `identifier`。

首次登录或已绑定因子但尚未完成验证时响应 `202`，不会设置 Session Cookie：

```json
{"status":"factor_setup_required","login_ticket":"opaque-ticket","methods":["totp","passkey"]}
```

已绑定因子时 `status` 为 `factor_required`，`methods` 只包含已绑定方式。TOTP 登录可在本请求中携带当前六位 `totp_code`；passkey 使用下面的 WebAuthn challenge 接口。

因子完成后响应 `200`：

```json
{"session_id":"uuid","expires_at":"2026-08-04T00:00:00Z"}
```

同时设置 HttpOnly Session Cookie 和 CSRF Cookie。浏览器请求应使用 `credentials: "include"`。

### 首次 TOTP 绑定

1. `POST /api/v1/auth/totp/setup`，请求 `{"login_ticket":"opaque-ticket"}`，响应一次性返回 `secret_base32` 和 `otpauth_url`。前端可将 URI 交给 Google Authenticator 扫描；服务端不返回二维码图片。
2. `POST /api/v1/auth/totp/setup/confirm`，请求 `{"login_ticket":"opaque-ticket","code":"123456"}`。验证码正确后保存加密秘钥、消费 ticket 并返回 Session Cookie；错误验证码不会消费 ticket。

### Passkey / WebAuthn

- `POST /api/v1/auth/passkeys/register/start`：请求 `login_ticket`，返回 WebAuthn `PublicKeyCredentialCreationOptions`。
- `POST /api/v1/auth/passkeys/register/finish`：请求 `login_ticket` 和浏览器 `navigator.credentials.create()` 返回的 `credential`，验证通过后保存公开凭据并返回 Session。
- `POST /api/v1/auth/passkeys/authentication/start`：请求 `login_ticket`，返回 `PublicKeyCredentialRequestOptions`。
- `POST /api/v1/auth/passkeys/authentication/finish`：请求 `login_ticket` 和浏览器 `navigator.credentials.get()` 返回的 `credential`，验证通过后更新 credential counter、消费 ticket 并返回 Session。

所有 `login_ticket` 和 WebAuthn challenge 默认有效 5 分钟；ticket 是一次性的。WebAuthn 的 RP ID 和 origin 由固定配置 `WEBAUTHN_RP_ID`、`WEBAUTHN_ORIGIN` 控制，不能从请求 Host 推导。

浏览器 OAuth 登录在密码步骤后也必须完成 TOTP；服务端页面会将首次绑定的 `otpauth://` URI 和验证码表单提交到 `POST /auth/login/totp`，成功后才绑定 OAuth 授权请求并跳转到授权确认页。仅有 passkey 的浏览器客户端应使用上述 WebAuthn API 完成因子后再继续授权。

### `DELETE /api/v1/auth/session`

撤销当前用户 Session，响应 `204` 并清理 Cookie。开发期也支持 `X-Chenxing-Session: <session_id>`；浏览器应使用 Cookie。

使用 Cookie 时必须同时发送：

- Session HttpOnly Cookie
- CSRF Cookie
- `X-CSRF-Token`，且值与 CSRF Cookie 和 Session 内 Token 一致

### 用户中心 UI API

- `GET /api/v1/auth/status`：返回当前是否登录。
- `GET /api/v1/auth/me`：返回当前用户资料和当前 Session 到期时间。
- `PATCH /api/v1/auth/me`：更新 `display_name`，需要用户 CSRF。
- `POST /api/v1/auth/password`：校验当前密码并修改密码，成功返回 `204`，同时撤销该用户所有 Session。
- `GET /api/v1/auth/sessions`：返回当前用户的 Session 元数据，不返回 Session 或 CSRF 秘密。
- `DELETE /api/v1/auth/sessions/{session_id}`：撤销当前用户拥有的指定 Session，需要用户 CSRF。

普通用户 OAuth 项目接口：

- `GET /api/v1/auth/oauth-clients`：只返回当前用户拥有的项目。
- `POST /api/v1/auth/oauth-clients`：创建项目，Secret 只返回一次；每个普通用户最多拥有 2 个项目，禁用项目仍占用配额。
- `PUT /api/v1/auth/oauth-clients/{client_id}`：更新自己的项目，需要用户 CSRF。
- `POST /api/v1/auth/oauth-clients/{client_id}/disable`、`/enable`：切换自己的项目状态，需要用户 CSRF。
- `POST /api/v1/auth/oauth-clients/{client_id}/rotate-secret`：轮换自己的 Secret，只返回新 Secret 一次，需要用户 CSRF。

每个普通用户项目的 OAuth 授权配额按 UTC 统计：每天最多 `2500` 次、每月最多 `50000` 次。项目响应中的 `quota` 包含 `daily_limit`、`daily_used`、`monthly_limit`、`monthly_used`。管理员创建的全局 OAuth Client 不受普通用户项目配额限制。普通用户不能访问 `/api/v1/admin/*`，也没有用户列表权限。

## OAuth 2.0 / OIDC

### `GET /oauth/authorize`

授权码入口，成功后重定向到注册的 `redirect_uri`，附带 `code` 和原始 `state`。

必填查询参数：

| 参数 | 说明 |
| --- | --- |
| `client_id` | 已注册 Client ID |
| `redirect_uri` | 必须精确匹配注册值 |
| `response_type` | 当前仅支持 `code` |
| `scope` | 空格分隔，如 `openid email profile` |
| `state` | 必填，建议由接入方随机生成 |
| `code_challenge` | PKCE challenge |
| `code_challenge_method` | 必须为 `S256` |
| `nonce` | 使用 OIDC 时建议必填并随机生成 |

未登录的浏览器请求会重定向到 `/auth/login?request_id=...`；非 HTML 请求返回 `401 login_required`。首次授权会进入 `/oauth/authorize/consent?request_id=...`。

### `GET /api/v1/oauth/authorize/requests/{request_id}` / `POST ...`

供 JSON 授权确认 UI 使用。请求必须绑定当前浏览器 Session；GET 返回 Client 名称、Redirect 主机、Scope 和剩余有效时间。POST JSON 请求为 `{"decision":"approve"}` 或 `{"decision":"deny"}`，需要用户 CSRF，成功返回经过校验的 `redirect_to`，请求被一次性消费。普通用户项目超过日/月配额时返回 `429 oauth_quota_exceeded`；标准 `/oauth/authorize` 流程返回协议安全的 `temporarily_unavailable` 重定向。

### `GET /auth/login` / `POST /auth/login`

浏览器登录页面，仅用于 OAuth 浏览器流程。登录表单字段为 `request_id`、`identifier`（用户名或邮箱）、`password`，成功后继续原授权请求。前端 SPA 一般不需要直接调用此 HTML 接口。

### `GET /oauth/authorize/consent` / `POST /oauth/authorize/consent`

浏览器授权确认页面。表单字段为 `request_id`、`decision`（允许值通常为 `approve` 或 `deny`）。状态变更需要浏览器 Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。

### `POST /oauth/token`

必须使用表单编码。Client 认证二选一：HTTP Basic `Authorization: Basic base64(client_id:client_secret)`，或表单中的 `client_id` + `client_secret`，不能同时使用。

授权码交换：

```text
grant_type=authorization_code&code=...&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier=...
```

刷新 Token：

```text
grant_type=refresh_token&refresh_token=...
```

成功响应 `200`：

```json
{"access_token":"...","token_type":"Bearer","expires_in":604800,"scope":"openid email","refresh_token":"...","id_token":"..."}
```

`refresh_token` 会轮换；包含 `openid` Scope 时返回 `id_token`。授权码和刷新 Token 均为一次性消费。

### `GET /oauth/userinfo`

请求头：`Authorization: Bearer <access_token>`。

响应字段按 Scope 返回：

```json
{"sub":"1","email":"user@example.com","name":"显示名称"}
```

### `POST /oauth/revoke`

表单字段：`token` 必填，`token_type_hint` 可选（`access_token` 或 `refresh_token`），并使用同 Token 端点的 Client 认证方式。成功响应 `200` 且无响应体。

## 管理 API

管理员 Bearer Token 请求头：`Authorization: Bearer <ADMIN_TOKEN>`。初始化完成后，管理员 API 使用 Bearer Token 或管理员 Session；`ADMIN_TOKEN` 为空时拒绝 Bearer Token 管理请求。

管理员 Session 登录后，管理写操作使用独立的管理员 Session/CSRF Cookie，并要求 `X-CSRF-Token`。管理员角色：`owner`、`operator`、`auditor`。

### `POST /api/v1/admin/bootstrap`

仅用于初始化首个管理员，无需认证。只有 `admins` 表为空时请求才会成功；初始化使用数据库并发锁保证最多创建一个管理员，成功后不可重复初始化。管理员不需要邮箱，只设置用户名和密码，首个管理员角色固定为 `owner`。

```json
{"username":"chenxing-admin","password":"at-least-10-chars"}
```

成功响应包含管理员 `id` 和 `role`，不会自动创建管理员 Session。

### `GET /api/v1/admin/bootstrap/status`

公开查询初始化状态，响应为 `{"initialized":false}` 或 `{"initialized":true}`。Web 前端首次打开时先查询此接口；状态为未初始化时显示管理员初始化界面。

### `POST /api/v1/admin/auth/login`

```json
{"username":"chenxing-admin","password":"at-least-10-chars"}
```

响应：`{"admin_id":1,"expires_in":604800}`，同时设置管理员 Session 和 CSRF Cookie。首个初始化管理员的 ID 为 `1`。

### `DELETE /api/v1/admin/auth/logout`

撤销管理员 Session，要求管理员 Session Cookie、管理员 CSRF Cookie 和 `X-CSRF-Token`；响应 `204`。

### 注册邮件发件地址

管理员 Web 控制台入口为 `/admin-console/login`，登录后在“邮件设置”页面维护用户注册流程使用的发件地址。该设置使用独立的管理员 Session Cookie、管理员 CSRF Cookie 和 `X-CSRF-Token` 保护，只有 Owner 可修改。

- `GET /api/v1/admin/settings/registration-email`：读取当前发件地址，未配置时返回 `{"registration_email_from":null}`。
- `PUT /api/v1/admin/settings/registration-email`：更新发件地址，提交 `{"registration_email_from":"no-reply@example.com"}`；传 `null` 或空字符串可清除配置，成功返回更新后的设置。

发件地址保存于 PostgreSQL 的 `app_settings` 表，不从环境变量、请求 Host 或前端状态推导。当前设置资源只保存地址本身；SMTP 连接参数、发送凭据和邮件模板属于后续邮件服务接入边界。

### 用户管理

- `GET /api/v1/admin/users`：列出用户，需要 `ManageUsers`。
- `POST /api/v1/admin/users/{user_id}/{status}`：设置用户状态，需要 `ManageUsers`。状态由后端支持值决定，常用为 `active`、`disabled`；成功 `204`。

用户列表元素：`id`、`username`、`email`、`display_name`、`status`、`created_at`。

### 管理员管理

- `GET /api/v1/admin/admins`：列出管理员，需要 `ManageUsers`。
- `POST /api/v1/admin/admins`：创建管理员，需要 Owner 权限和管理员 CSRF。

创建字段：`username`、`password`、`role`。返回的管理员摘要不包含密码或哈希。

### Client 管理

请求字段：

```json
{"client_name":"我的应用","redirect_uris":["https://app.example/callback"],"scopes":["openid","email"]}
```

- `POST /api/v1/admin/clients`：创建 Client，需要 `ManageClients`。响应包含 `client_secret`，只返回这一次。
- `GET /api/v1/admin/clients`：列出 Client，不返回 Secret 或其哈希。
- `PUT /api/v1/admin/clients/{client_id}`：更新配置，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/disable`：禁用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/enable`：启用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/rotate-secret`：轮换 Secret，成功响应包含新的 `client_id` 和 `client_secret`，只显示新 Secret 一次。

Client 列表元素包含：`id`、`client_id`、`client_name`、`redirect_uris`、`scopes`、`status`、`owner_user_id`。不返回 Secret 或其哈希。

### `GET /api/v1/admin/audit?limit=50`

查询审计事件，需要 `ReadAudit`。`limit` 可选，默认 50。

### `POST /api/v1/admin/keys/rotate`

轮换 RS256 签名密钥，需要 `RotateKeys`。响应：

```json
{"key_id":"...","published_key_count":2}
```

### 管理后台 UI API

- `GET /api/v1/admin/auth/me`：返回管理员角色、权限和身份摘要。Owner 是最高级角色，拥有全部权限。
- `GET /api/v1/admin/overview`：返回全局用户、OAuth Client、管理员和审计计数。
- `GET /api/v1/admin/users/query?page=1&page_size=20&search=...&status=active`：分页筛选用户，需要 `ManageUsers`。
- `GET /api/v1/admin/clients/query?page=1&page_size=20&search=...&status=active`：分页筛选全局 Client，需要 `ManageClients`，返回 owner ID 但不返回 Secret。
- `GET /api/v1/admin/audit/query?page=1&page_size=20&action=...&resource_type=...`：分页筛选审计，需要 `ReadAudit`。

分页响应统一为 `{"items":[],"page":1,"page_size":20,"total":0}`。管理员 API 继续支持 Bearer Token；浏览器 Session 写操作仍必须使用管理员 CSRF Cookie 和 `X-CSRF-Token`。

## 权限矩阵

| 角色 | 用户/管理员 | Client | 审计 | 密钥轮换 |
| --- | --- | --- | --- | --- |
| `owner` | 是 | 是 | 是 | 是 |
| `operator` | 是 | 是 | 否 | 否 |
| `auditor` | 否 | 否 | 是 | 否 |

## 前端接入建议

1. SPA 登录优先调用 `/api/v1/auth/login`，保留响应 Cookie，并将 CSRF Cookie 读取后放入写请求的 `X-CSRF-Token`。
2. OAuth 接入使用 Authorization Code + PKCE S256；`state` 和 `nonce` 必须由接入方生成并校验。
3. Token 交换和撤销必须由受信任后端完成，避免把 Client Secret 放进浏览器代码。
4. 生产环境使用 HTTPS，并确保 `COOKIE_SECURE=true`。
