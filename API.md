# 辰星认证中枢 API

本文档以当前后端代码实际暴露的接口为准，供前端和 OAuth/OIDC 接入方使用。

## 基础约定

- Base URL 使用部署后的认证服务地址，例如 `https://auth.example.com`。
- JSON 请求发送 `Content-Type: application/json`；OAuth Token 和 Revocation 请求发送 `application/x-www-form-urlencoded`。
- 时间使用 RFC 3339 字符串，ID 使用 UUID 字符串。
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
{"email":"user@example.com","password":"at-least-12-chars","display_name":"显示名称"}
```

`display_name` 可省略或为 `null`，最长 128 个字符；密码至少 12 个字符。

响应 `201`：

```json
{"user":{"id":"uuid","email":"user@example.com","display_name":"显示名称","status":"active","created_at":"2026-07-28T00:00:00Z"}}
```

常见错误：`invalid_email`、`password_too_short`、`display_name_too_long`、`email_already_registered`。

### `POST /api/v1/auth/login`

请求：

```json
{"email":"user@example.com","password":"at-least-12-chars"}
```

响应 `200`：

```json
{"session_id":"uuid","expires_at":"2026-08-04T00:00:00Z"}
```

同时设置 HttpOnly Session Cookie 和 CSRF Cookie。浏览器请求应使用 `credentials: "include"`。

### `DELETE /api/v1/auth/session`

撤销当前用户 Session，响应 `204` 并清理 Cookie。开发期也支持 `X-Chenxing-Session: <session_id>`；浏览器应使用 Cookie。

使用 Cookie 时必须同时发送：

- Session HttpOnly Cookie
- CSRF Cookie
- `X-CSRF-Token`，且值与 CSRF Cookie 和 Session 内 Token 一致

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

### `GET /auth/login` / `POST /auth/login`

浏览器登录页面，仅用于 OAuth 浏览器流程。登录表单字段为 `request_id`、`email`、`password`，成功后继续原授权请求。前端 SPA 一般不需要直接调用此 HTML 接口。

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
{"sub":"user-uuid","email":"user@example.com","name":"显示名称"}
```

### `POST /oauth/revoke`

表单字段：`token` 必填，`token_type_hint` 可选（`access_token` 或 `refresh_token`），并使用同 Token 端点的 Client 认证方式。成功响应 `200` 且无响应体。

## 管理 API

管理员 Bearer Token 请求头：`Authorization: Bearer <ADMIN_TOKEN>`。`ADMIN_TOKEN` 为空时所有管理员 API 都拒绝访问。

管理员 Session 登录后，管理写操作使用独立的管理员 Session/CSRF Cookie，并要求 `X-CSRF-Token`。管理员角色：`owner`、`operator`、`auditor`。

### `POST /api/v1/admin/bootstrap`

仅用于初始化首个管理员，使用 `ADMIN_TOKEN` Bearer 认证；成功后不可重复初始化。

```json
{"email":"admin@example.com","password":"at-least-12-chars","role":"owner"}
```

成功响应包含管理员 `id` 和 `role`。

### `POST /api/v1/admin/auth/login`

```json
{"email":"admin@example.com","password":"at-least-12-chars"}
```

响应：`{"admin_id":"uuid","expires_in":604800}`，同时设置管理员 Session 和 CSRF Cookie。

### `DELETE /api/v1/admin/auth/logout`

撤销管理员 Session，要求管理员 Session Cookie、管理员 CSRF Cookie 和 `X-CSRF-Token`；响应 `204`。

### 用户管理

- `GET /api/v1/admin/users`：列出用户，需要 `ManageUsers`。
- `POST /api/v1/admin/users/{user_id}/{status}`：设置用户状态，需要 `ManageUsers`。状态由后端支持值决定，常用为 `active`、`disabled`；成功 `204`。

用户列表元素：`id`、`email`、`display_name`、`status`、`created_at`。

### 管理员管理

- `GET /api/v1/admin/admins`：列出管理员，需要 `ManageUsers`。
- `POST /api/v1/admin/admins`：创建管理员，需要 Owner 权限和管理员 CSRF。

创建字段：`email`、`password`、`role`。返回的管理员摘要不包含密码或哈希。

### Client 管理

请求字段：

```json
{"client_id":"my-app","client_name":"我的应用","redirect_uris":["https://app.example/callback"],"scopes":["openid","email"]}
```

- `POST /api/v1/admin/clients`：创建 Client，需要 `ManageClients`。响应包含 `client_secret`，只返回这一次。
- `GET /api/v1/admin/clients`：列出 Client，不返回 Secret 或其哈希。
- `PUT /api/v1/admin/clients/{client_id}`：更新配置，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/disable`：禁用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/enable`：启用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/rotate-secret`：轮换 Secret，成功响应包含新的 `client_id` 和 `client_secret`，只显示新 Secret 一次。

Client 列表元素包含：`id`、`client_id`、`client_name`、`redirect_uris`、`scopes`、`status`。

### `GET /api/v1/admin/audit?limit=50`

查询审计事件，需要 `ReadAudit`。`limit` 可选，默认 50。

### `POST /api/v1/admin/keys/rotate`

轮换 RS256 签名密钥，需要 `RotateKeys`。响应：

```json
{"key_id":"...","published_key_count":2}
```

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
