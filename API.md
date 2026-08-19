# 辰星认证中枢 API

本文档以当前后端代码实际暴露的接口为准，供前端和 OAuth/OIDC 接入方使用。

## 基础约定

- Base URL 使用部署后的认证服务地址，例如 `https://auth.example.com`。
- JSON 请求发送 `Content-Type: application/json`；OAuth Token 和 Revocation 请求发送 `application/x-www-form-urlencoded`。
- 所有 `application/json` 请求体使用同一解析契约：缺少或使用错误的 `Content-Type` 返回 `415 unsupported_media_type`，JSON 语法错误返回 `400 invalid_json`，字段类型或必填字段错误返回 `422 invalid_json`。这些响应都使用 `{code,message}`，不会回显 serde 字段路径、Rust 类型或解析器内部信息。
- 时间使用 RFC 3339 字符串；用户、Session、OAuth Client、认证因子、外部身份、提供商和审计事件的数据库内部 ID 是从 1 开始递增的整数。Client ID、提供商 slug、Session Token、授权码等协议或凭据标识仍使用字符串。
- 认证失败、参数错误等 JSON 错误统一为：

```json
{"code":"invalid_credentials","message":"email or password is incorrect"}
```

- OAuth 协议端点（`/oauth/*`，如 `/oauth/token`、`/oauth/authorize`、`/oauth/revoke`、`/oauth/userinfo`）的 JSON 错误遵守 RFC 6749，字段为 `error` / `error_description`，**不是**上面的内部 `{code, message}` 信封。内部授权确认 API（`/api/v1/oauth/*`）仍使用内部信封。
- 请求超时（`REQUEST_TIMEOUT_SECONDS`，默认 30 秒；健康检查与静态 SPA fallback 不受此限制）和已配置 Issuer 的运行态门禁失败按协议边界分流响应格式（Issues #423、#441、#451）：
  - 已注册的 `/oauth/authorize`、`/oauth/token`、`/oauth/revoke`、`/oauth/userinfo`：`503` + RFC 6749 `{"error":"temporarily_unavailable","error_description":"..."}`，与依赖暂不可用等协议错误一致；未知 `/oauth/*` 路径仍返回统一 404。
  - 其余已匹配的应用路由，以及 system 路由（`/api/v1/admin/bootstrap`、`/api/v1/admin/bootstrap/status`、`/api/v1/admin/settings/issuer`）：`504` + `{"code":"request_timeout","message":"request timed out"}`。
- 常见状态码：`200` 成功，`201` 创建成功，`204` 成功且无响应体，`400` 参数或业务校验失败，`401` 未认证，`403` 无权限，`409` 冲突，`413` JSON 请求体超过上限，`503` 依赖暂不可用，`504` 非 OAuth 路由请求超时，`500` 服务端错误。
- 不要在前端日志中记录密码、Client Secret、Session、授权码或 Token。
- 共享 Redis 的每个部署必须配置不同的 `REDIS_NAMESPACE`（1–64 位 ASCII 字母、数字、`.`、`_` 或 `-`）。新安装器会生成一次性随机值；手工部署可用 `openssl rand -hex 16` 生成并持久化，禁止在多个安装间复用。只有升级前已使用无前缀键的部署才应省略该变量或显式设为 `legacy`；这是滚动升级兼容模式，不是新生产部署默认值。生产 Compose 会在变量缺失或为空时直接失败。legacy 模式启动时会明确告警，日志始终不会记录 `REDIS_URL` 或凭据。

## 健康和 OIDC 元数据

### `GET /health/live`

存活探针。只报告进程本身，不触碰数据库、Redis 或 Issuer，恒返回 `200`：

```json
{"status":"ok","service":"chenxing-auth"}
```

### `GET /health` 与 `GET /health/ready`

就绪探针。`/health` 是 `/health/ready` 的兼容别名，两者检查数据库、Redis、Issuer 收敛、四个关键后台 worker 的心跳/最近成功，以及签名密钥同步状态。数据库、Redis、worker 和签名同步正常且 Issuer 尚未设置时，保护模式同样返回 `200`，不会因为缺少 Issuer 把 readiness/health 置为 `503`。任一实际依赖超时或未就绪、worker 未成功启动/心跳过期/连续失败，或签名密钥同步异常时返回 `503`：

```json
{"status":"unavailable","service":"chenxing-auth"}
```

响应体只暴露聚合状态，不含连接串、主机名或错误细节。

### `GET /.well-known/openid-configuration`

返回 OIDC Discovery 文档。前端/接入方应优先读取该文档，不要硬编码协议端点。当前至少包含 `issuer`、`authorization_endpoint`、`token_endpoint`、`userinfo_endpoint`、`jwks_uri`、`revocation_endpoint` 等标准字段。

保护模式尚未设置 Issuer 时，该端点关闭；完成 Owner 设置并热更新后才提供 Discovery。

Discovery 是公开只读元数据，允许任意来源跨域读取：请求带 `Origin` 时响应 `Access-Control-Allow-Origin: *`；无论是否带 Origin 都响应 `Vary: Origin`，避免共享缓存混用 CORS 变体。该端点不读取 Cookie 或 Authorization，`*` 与不带凭据的请求兼容。

### `GET /.well-known/jwks.json`

返回当前及验证过渡期公钥集合。只用于验证 JWT，不包含私钥。

保护模式尚未设置 Issuer 时，该端点关闭；它只服务于正式 Issuer 下签发的令牌。

JWKS 是被 RP 高频轮询的公开端点，缓存策略为 `Cache-Control: public, max-age=60, must-revalidate`：

- RP 可在 60 秒内直接使用共享缓存副本，不必每次回源；
- 60 秒远短于密钥保留窗口（默认 7 天），轮换或吊销后最迟 60 秒全网看到新公钥；
- `must-revalidate` 阻止缓存在回源失败时返回陈旧 JWKS——陈旧公钥会让新签发的令牌验签失败。

响应携带确定性 ETag（JWKS 字节的 SHA-256 强 ETag，跨实例一致）。RP 应在本地缓存过期后用 `If-None-Match` 发起条件请求：公钥集合未变时返回 `304 Not Modified`（仍带 ETag 与 Cache-Control），避免重复传输完整 JWKS。密钥轮换或吊销改变公钥集合后 ETag 随之改变，RP 拿到新 ETag 和新 JWKS。

JWKS 的 CORS 与 Discovery 一致：请求带 `Origin` 时 `Access-Control-Allow-Origin: *`（不带凭据），始终 `Vary: Origin`；200 与 304 均适用。另返回 `Access-Control-Expose-Headers: ETag`：`ETag` 不是 CORS 安全列表响应头，浏览器 JS 必须靠该头才能读取并用于后续 `If-None-Match`。该头只出现在 JWKS，不扩到 Discovery 或其它路由。

## 用户和浏览器 Session

### `POST /api/v1/users`

创建辰星通行证账号。

当前公开注册在真实的邮件投递和验证令牌消费能力接入前 fail-closed：格式合法的请求返回 `503` 和 `email_verification_unavailable`，不会创建 active 用户，也不会写入无期限的待验证身份。保护模式下还会以 `503 issuer_not_configured` 拒绝注册。系统不会把邮件标记为已验证，也不会在响应中返回验证令牌。

请求：

```json
{"username":"chenxing-user","email":"user@example.com","password":"at-least-10-chars","display_name":"显示名称"}
```

`username` 必填，长度 3-64 个字符，仅允许 ASCII 字母、数字、点号、下划线和连字符；首尾空白会被裁剪，必须唯一，且不区分大小写的 `admin`、`administrator`、`owner`、`root`、`system` 等系统保留名不可使用。`display_name` 可省略或为 `null`，最长 128 个字符；密码至少 10 个字符。

验证投递能力接入后，成功响应 `201`：

```json
{"user":{"id":1,"username":"chenxing-user","email":"user@example.com","display_name":"显示名称","status":"active","created_at":"2026-07-28T00:00:00Z"}}
```

常见错误：`invalid_username`、`invalid_email`、`password_too_short`、`display_name_too_long`、`registration_conflict`、`email_verification_unavailable`。

公开注册的用户名和邮箱唯一冲突统一返回 `registration_conflict`，不暴露具体冲突字段。数据库仍保留 `users.username` 和 `users.email` 的独立唯一约束，避免绕过接口检查破坏身份完整性。

### `POST /api/v1/auth/login`

请求：

```json
{"identifier":"chenxing-user","password":"at-least-10-chars","totp_code":"123456"}
```

`identifier` 可以填写普通用户注册时的 `username` 或邮箱地址。为兼容旧客户端，服务端仍接受请求体中的 `email` 别名；新客户端应使用 `identifier`。

`identifier` 上限 254 字符，`password` 上限 128 字符，与注册侧的口令长度上界一致。超出上界的请求在进入口令哈希、数据库查询和失败限流之前被拒绝，响应与凭据错误完全相同（`401` + `invalid_credentials`），不返回独立错误码，也不暴露账号是否存在。登录不校验口令长度下界，存量短口令仍可登录。

已绑定 TOTP 但尚未完成验证时响应 `202`，并设置短期 HttpOnly pending-login Cookie：

```json
{"status":"factor_required","methods":["totp"]}
```

`methods` 只发布 `totp`。Passkey 是独立的无密码登录方式，不会在密码验证成功后再次作为二次因子出现。ticket 不再出现在普通 JSON 响应中，而是由 `HttpOnly`、`SameSite=Lax` 的 pending-login Cookie 携带，并绑定同一响应下发的独立 holder Cookie。TOTP 登录可在本请求中携带当前六位 `totp_code`。账号没有绑定 TOTP 时，密码登录直接响应 `200` 并签发普通 Session；用户登录后可通过安全设置 API 绑定 TOTP 或 Passkey。

HTTPS 部署使用 `__Host-chenxing_login_ticket` 和 `__Host-chenxing_login_holder`；仅在 loopback HTTP 本地开发时使用 `chenxing_login_ticket` 和 `chenxing_login_holder`。两个 Cookie 都是 `Path=/`、`HttpOnly`、`SameSite=Lax`，成功签发 Session 后立即清理。

因子完成后响应 `200`：

```json
{"expires_at":"2026-08-04T00:00:00Z"}
```

同时设置 HttpOnly Session Cookie 和 CSRF Cookie。HTTPS 部署使用 `__Host-chenxing_session` 与 `__Host-chenxing_csrf`，它们固定为 `Secure; Path=/` 且不带 `Domain`，由浏览器强制 host-only 约束。仅在 loopback HTTP 本地开发时才允许 `COOKIE_SECURE=false`，此时使用不带前缀的兼容名称。浏览器请求应使用 `credentials: "include"`，再通过 `/api/v1/auth/status` 和 `/api/v1/auth/me` 确认登录状态。默认不会将可直接使用的 Session token 放入 JSON；非浏览器兼容调用只有在服务端 `SESSION_TOKEN_RESPONSE_ENABLED=true` 且显式发送 `X-Chenxing-Session-Mode: token` 时才会收到 `session_id`。

Session 同时有固定的绝对截止时间和可滑动的空闲窗口：`SESSION_TTL_SECONDS` 控制绝对期限，`SESSION_IDLE_TIMEOUT_SECONDS` 控制连续无活动期限。成功认证请求会在空闲窗口过半时更新服务端 `last_seen_at`，但不会改变绝对 `expires_at`；Redis TTL 取两者较早者。每个用户的活跃 Session 数受 `SESSION_MAX_CONCURRENT_SESSIONS` 限制，达到上限时最早的活跃 Session 会被撤销。

### 首次 TOTP 绑定

1. `POST /api/v1/auth/totp/setup`，请求 `{}`（旧客户端可附带 `login_ticket`，但必须与 HttpOnly Cookie 完全一致），响应一次性返回 `secret_base32` 和 `otpauth_url`。前端应使用项目内二维码组件将 `otpauth_url` 作为二维码内容本地生成二维码；`secret_base32` 仅用于无法扫描时手动输入或复制。服务端不调用第三方二维码服务，也不返回二维码图片。该端点与已登录安全中心的 `POST /api/v1/auth/security/totp/enrollment/start` 都从已加载 Issuer 生成 otpauth 标签；Issuer 门禁回读后仍不可用时返回 `503 issuer_not_configured` / `issuer_runtime_invalid`，不会创建 pending 注册。
2. `POST /api/v1/auth/totp/setup/confirm`，请求 `{ "code":"123456" }`。验证码正确后保存加密秘钥、消费 ticket 并返回 Session Cookie；错误验证码不会消费 ticket。

已有 TOTP 的待处理登录也可以调用 `POST /api/v1/auth/totp/login`，请求包含当前六位 `code`。验证码正确后消费 ticket 并返回 Session Cookie；无效或缺少 holder proof 的 ticket 返回 `400`，错误验证码返回 `401`。

验证码在同一时间步内只能使用一次，边界按「用户 + 时间步」判定，与走的是绑定确认还是登录验证无关：绑定确认消费掉的验证码不能再用于 `POST /api/v1/auth/totp/login` 或带 `totp_code` 的密码登录，换一张新的 login ticket 也不行，反向同理。命中这种冲突时返回 `401`，ticket 和待确认注册都保留，等下一个验证码重试即可。

### Passkey / WebAuthn

- `POST /api/v1/auth/passkeys/discoverable/start`：无需账号或密码，请求 `{}`，返回不含凭据白名单的 WebAuthn challenge。
- `POST /api/v1/auth/passkeys/discoverable/finish`：提交 `challenge_id` 和浏览器 `navigator.credentials.get()` 返回的 `credential`；认证器通过可发现凭据的 `userHandle` 标识账号。账号未绑定 TOTP 时直接签发 Session；已绑定 TOTP 时响应 `202` 与 `{"status":"factor_required","methods":["totp"]}`，继续进入验证器应用确认。
- `POST /api/v1/auth/passkeys/register/start`：请求 `{}`，返回 WebAuthn `PublicKeyCredentialCreationOptions`。
- `POST /api/v1/auth/passkeys/register/finish`：请求浏览器 `navigator.credentials.create()` 返回的 `credential`，验证通过后保存公开凭据并返回 Session Cookie。
- `POST /api/v1/auth/passkeys/authentication/start`：请求 `{}`，返回 `PublicKeyCredentialRequestOptions`。
- `POST /api/v1/auth/passkeys/authentication/finish`：请求浏览器 `navigator.credentials.get()` 返回的 `credential`，验证通过后更新 credential counter、消费 ticket 并返回 Session Cookie。

管理员通过 `PUT /api/v1/admin/settings/passkey` 禁用 Passkey 时，如果存在活跃且唯一绑定 Passkey 的账号，服务端返回 `409 passkey_disable_blocked`，设置不会变更。这样已绑定 Passkey 的账号不会因全局策略被锁定；禁用后新的登录因子响应和首次绑定选项只发布 TOTP。

所有 pending-login Cookie、`login_ticket` 和 WebAuthn challenge 默认有效 5 分钟；ticket 是一次性的。Redis 中只保存 holder Cookie 的摘要，不保存 holder 原值；缺少 holder、Cookie 中 ticket 与旧请求字段不一致、或升级前无 holder 摘要的 ticket 都 fail closed，需要重新开始登录。WebAuthn 的 RP ID 和 origin 不能从请求 Host 或反向代理输入推导：显式配置 `WEBAUTHN_RP_ID`、`WEBAUTHN_ORIGIN` 时固定使用覆盖值；未显式配置时，在持久化 Issuer 加载后分别从其 host 和根 URL 派生，并随 Issuer generation 原子更新。通用 `.env.example` 不再永久固定 loopback 值；本地 HTTP 开发使用 `.env.loopback.example` 中的明确覆盖。

浏览器 OAuth 登录现在由 React SPA 承接。密码步骤调用 `POST /api/v1/auth/login`，密码登录后的二次确认只使用 TOTP；“Auth 登录”页签可直接调用 discoverable Passkey 接口，无需先提交账号和密码。Passkey 只替代密码这一步：账号若已启用验证器应用，Passkey 成功后仍必须完成 TOTP。所有必要验证完成后，SPA 调用授权请求绑定接口并继续授权确认。

### `DELETE /api/v1/auth/session`

撤销当前用户 Session，响应 `204` 并清理 Cookie。身份只从 HttpOnly Session Cookie 读取，`X-Chenxing-Session` 请求头不再被该端点接受。

撤销是状态变更，必须无条件同时发送：

- Session HttpOnly Cookie
- CSRF Cookie
- `X-CSRF-Token`，且值与 CSRF Cookie 和 Session 内 Token 一致

### 用户中心 UI API

- `GET /api/v1/auth/status`：返回当前是否登录。没有会话或会话已失效时返回 `authenticated: false`；数据库或 Session 存储故障返回 `500 internal_error`，不会伪装成未登录。
- `GET /api/v1/auth/me`：返回当前用户资料和当前 Session 到期时间。
- `PATCH /api/v1/auth/me`：更新 `display_name`，需要用户 CSRF。
- `POST /api/v1/auth/password`：校验当前密码并修改密码，成功返回 `204`，同时撤销该用户所有 Session。当前密码为空或超过 128 字符时与密码错误返回同一 `401 invalid_credentials`，不暴露长度。
- `GET /api/v1/auth/entitlements`：返回当前生效套餐摘要（`code`、`name`、`description`、`validity`）和各项权益用量；`limit` 为 `null` 表示无限，缺失表示数值无上限概念（如 QPS）。
- `GET /api/v1/auth/security-events?page=1&page_size=20`：分页返回当前用户在热表和归档表中的安全事件，包含 `id`、`action`、`category`、`severity`、`resource_type`、OAuth Client 摘要和时间；`page_size` 最大为 100。`category`/`severity` 由服务端单点映射，未映射的 action 回落 `account`/`info`。
- `GET /api/v1/auth/security-events/{event_id}`：返回单个安全事件详情（`ip`/`user_agent` 只从 metadata 白名单提取，`ip_location`/`ray_id` 恒为 null，`client` 仅 OAuth 事件填充、Client 已删除时为 null）；事件不存在或不属于当前用户时一律 404，不区分「查不到」与「不是你的」。
- `GET /api/v1/auth/sessions`：返回当前用户的 Session 元数据，不返回 Session 或 CSRF 秘密。
- `DELETE /api/v1/auth/sessions/{session_id}`：撤销当前用户拥有的指定 Session，需要用户 CSRF。

普通用户 OAuth 项目接口：

- `GET /api/v1/auth/oauth-clients`：只返回当前用户拥有的项目。
- `POST /api/v1/auth/oauth-clients`：创建项目，Secret 只返回一次；项目数量上限来自当前生效套餐的 `oauth_clients_limit`（默认套餐为 2），禁用项目仍占用配额。
- `PUT /api/v1/auth/oauth-clients/{client_id}`：更新自己的项目，需要用户 CSRF。
- `POST /api/v1/auth/oauth-clients/{client_id}/disable`、`/enable`：切换自己的项目状态，需要用户 CSRF。
- `POST /api/v1/auth/oauth-clients/{client_id}/rotate-secret`：轮换自己的 Secret，只返回新 Secret 一次，需要用户 CSRF。

每个普通用户项目的 OAuth 授权配额按 UTC 统计，日/月上限来自用户当前生效套餐（默认套餐为每天 `2500` 次、每月 `50000` 次，`monthly_auth_limit` 为 `null` 表示不限）。项目响应中的 `quota` 包含 `daily_limit`、`daily_used`、`monthly_limit`、`monthly_used`；套餐的真实分母以 `GET /api/v1/auth/entitlements` 返回为准。管理员创建的全局 OAuth Client 不受普通用户项目配额限制。普通用户不能访问 `/api/v1/admin/*`，也没有用户列表权限。

## OAuth 2.0 / OIDC

### `GET /oauth/authorize` / `POST /oauth/authorize`

授权码入口。GET 使用查询参数，POST 使用 `application/x-www-form-urlencoded` 表单；两种方法的字段、校验和响应行为相同。成功后重定向到注册的 `redirect_uri`，附带 `code` 和原始 `state`。

Client 已加载且 `redirect_uri` canonicalize 后仍严格匹配注册值时，后续参数校验失败、Session/consent/pending 存储不可用、授权码签发失败等错误通过 `302` 返回该 canonical 回调地址，并携带 RFC 6749 `error` / `error_description`。注册匹配允许 URL parser 消除默认端口、补根斜杠，并保留 RFC 8252 loopback 字面 IP 的动态端口例外；授权码本身仍绑定授权请求提交的**原始** `redirect_uri` 文本，Token 兑换必须回送完全相同的值。只有非空且不超过 512 个字符的 `state` 才会回显。Client 或回调地址不可信时绝不重定向，改为 RFC 6749 JSON 错误信封；Issuer 门禁和请求超时发生在可信回调上下文建立之前，同样返回 `503 temporarily_unavailable` JSON。

必填请求字段（GET 为查询参数，POST 为表单字段）：

| 参数 | 说明 |
| --- | --- |
| `client_id` | 已注册 Client ID |
| `redirect_uri` | canonicalize 后必须匹配注册值（loopback 字面 IP 可变更端口）；授权码兑换时必须原样回送本次授权请求的文本 |
| `response_type` | 当前仅支持 `code` |
| `scope` | 空格分隔，如 `openid email profile`；每个值必须同时属于服务端 allowlist（默认 `openid`、`profile`、`email`）和该 Client 已注册的 scopes |
| `state` | 必填，建议由接入方随机生成，最多 512 个字符 |
| `code_challenge` | PKCE challenge |
| `code_challenge_method` | 必须为 `S256` |
| `nonce` | 使用 OIDC 时建议必填并随机生成，最多 512 个字符 |

未登录的浏览器请求会重定向到 React SPA 的 `/login?request_id=...`；已登录但尚未授权该 scope 组合的请求进入 `/oauth/consent?request_id=...`。两条交给 SPA 的路径都会下发授权持有者 HttpOnly Cookie：HTTPS 使用 `__Host-chenxing_authz_holder`，本地 HTTP 使用 `chenxing_authz_holder`（防御 OAuth login CSRF，见下文 bind 端点说明）。pending 请求同时保存本次 `/oauth/authorize` 捕获的 Issuer generation；Issuer 热切换后，旧 generation 的授权事务不能继续。非 HTML 请求返回 `401 login_required`。

### `POST /api/v1/oauth/authorize/requests/{request_id}/bind`

将当前浏览器 Session 绑定到 pending 授权请求。绑定完成后才能调用 inspect（GET）和 decide（POST）。

调用方必须同时提供：

| 凭据 | 来源 | 说明 |
| --- | --- | --- |
| Session Cookie `__Host-chenxing_session` | TOTP / 密码登录响应 | 身份认证 |
| CSRF Cookie `__Host-chenxing_csrf` + `X-CSRF-Token` | 同上 | 防 CSRF |
| 持有者 Cookie `__Host-chenxing_authz_holder`（HTTPS）或 `chenxing_authz_holder`（本地 HTTP） | `/oauth/authorize` 重定向响应 | **防 OAuth login CSRF（#115）** |

**授权持有者 Cookie 说明**：HTTPS 使用 `__Host-chenxing_authz_holder`，本地 HTTP 使用 `chenxing_authz_holder`。`request_id` 通过 URL 查询参数传递，可能通过 Referer、浏览器历史或分享链接泄露。没有持有者绑定，任何拿到 `request_id` 的已登录攻击者都可以把受害者的 pending 请求绑到自己的会话上并批准，使受害者登录进攻击者账号（OAuth login CSRF / 请求固定攻击）。

`/oauth/authorize` 在把浏览器交给 SPA 时下发该 Cookie（`HttpOnly; SameSite=Lax; Path=/`），其 SHA-256 摘要存入 Redis。bind 端点比对 Cookie 值与摘要，不匹配返回 `403 authorization_holder_invalid`。

升级前创建的旧 pending 记录无摘要，绑定时被拒绝（fail-secure），用户需重新发起授权流程。

**受控重绑（#270）**：上述三项校验全部通过时，无论该 pending 请求此前绑定的是哪个 Session 摘要，都会被重绑到调用者当前的 Session，写入走 CAS 保证原子性。持有者 Cookie 才是所有权凭据，Session 绑定是派生状态，因此重绑不放宽任何安全边界——没有持有者 Cookie 的第三方即使持有有效 Session 仍然被拒（`403`）。这让「会话过期后重新登录继续授权」和「切换账号继续授权」可以自愈；旧行为固定返回 `401 invalid_session`，前端跟着在登录页与授权确认页之间形成跳转循环。授权码在最终 approve 时按当时持有的 Session 签发。重绑记录审计事件 `authorization_request_rebound`。重绑只替换绑定载荷并保留 Redis 请求键的原始剩余 TTL 和 expiry 索引截止时间；重复重绑不能延长 pending 的总生命周期，临界过期请求也不会被恢复为完整 TTL。

幂等：同一 Session + 同一持有者 Cookie 重复调用返回 `204`，载荷不变。持续并发修改导致 CAS 无法收敛时返回 `409 authorization_request_conflict`，重试即可。

### `GET /api/v1/oauth/authorize/requests/{request_id}` / `POST ...`

供 JSON 授权确认 UI 使用。请求必须绑定当前浏览器 Session，并且 pending 的 Issuer generation 必须等于本次请求捕获的 Issuer generation；Issuer 热切换后或升级前缺失 generation 的 pending 会被丢弃并返回 `400 authorization_request_expired`，Client 必须重新发起授权。GET 返回 Client 名称、Redirect 主机、Scope 和剩余有效时间。POST JSON 请求为 `{"decision":"approve"}` 或 `{"decision":"deny"}`，需要用户 CSRF，成功返回经过校验的 `redirect_to`，请求被一次性消费。该内部 UI API 的所有错误都使用 `{code, message}`，不会返回 OAuth `{error, error_description}` 信封。普通用户项目超过日/月配额时返回 `429 authorization_unavailable`；内部一致性故障返回 `500 internal_error`，依赖故障返回对应的 `503` 内部错误。标准 `/oauth/authorize` 流程则返回协议安全的 `temporarily_unavailable` 重定向。

### React SPA 浏览器登录 `/login`

浏览器登录页面由 React SPA 提供。登录请求统一使用 `POST /api/v1/auth/login`；页面通过 `GET /api/v1/auth/external-providers` 查询并显示已启用的自定义 OAuth 提供商。

### `GET /auth/external/{slug}` / `GET /auth/external/{slug}/callback`

开始并完成自定义外部 **OAuth 2.0** 登录。`slug` 来自管理员设置；开始请求可携带 `request_id` 以便登录后继续辰星的授权确认。系统使用一次性 Redis `state` 和 HttpOnly state Cookie 绑定浏览器流程，回调成功后创建辰星 Session。HTTPS 部署下发 `__Host-chenxing_external_oauth_state_<state 绑定标识>`，固定 `Secure; Path=/; HttpOnly; SameSite=Lax` 且不带 `Domain`；回调只接受这个 host-only Cookie，同站兄弟域投下的父域 `Domain` cookie 不会命中。仅 loopback HTTP 且 `COOKIE_SECURE=false` 时使用不带前缀的 `chenxing_external_oauth_state_*` 兼容名。流程结束或失败时按同一名称与属性清理该 Cookie。成功签发 Session 后会同时清理同浏览器残留的 pending-login ticket/holder Cookie；若请求里仍带有可解析的旧 ticket，服务端会尽力删除对应 Redis 记录。清理失败只记非敏感告警并由 TTL 兜底，不会撤销已经成功的外部登录。

#### 信任模型：OAuth 2.0 + UserInfo

自定义提供商是 **OAuth 2.0 授权码流程 + UserInfo 端点**，本平台在这一侧**不是 OIDC 依赖方**。管理 API 的 `trust_model` 字段恒为 `oauth2_userinfo`，明确这一语义：

- 身份字段来源只有一个：用 access token 经 TLS 调用 `userinfo_endpoint` 得到的 JSON。`sub`、`email`、`email_verified` 全部按 provider 配置的 claim 路径从该响应中读取。
- 令牌响应里的 `id_token` **不被解析、不被存储、不参与身份判定**。本平台不为自定义提供商保存 issuer、JWKS、允许算法或 nonce 策略，因此不具备验证 ID Token 签名、`kid`、`iss`、`aud`、`exp`、`iat` 和 `nonce` 的条件；把一个未验证的 JWT 当身份断言使用比丢弃它危险得多。
- 只返回 `id_token` 而没有 `access_token` 的令牌响应按失败处理，回跳 `external_error=oauth_login_failed`。
- `scopes` 里可以包含 `openid`——多数 OIDC 提供商需要它才开放 UserInfo 端点——但它在本平台只起「换取可调用 UserInfo 的 access token」的作用，不代表本平台执行了 OIDC 身份断言校验。
- `email_verified` 的可信度上限就是外部 UserInfo 响应本身。选择提供商时应确认该端点返回的验证状态是可信的。

本平台**作为 OP 对下游 Client 仍然完整支持 OIDC**（Discovery、RS256 ID Token、nonce 绑定、UserInfo），上面的限定只针对上游自定义提供商这一侧。

#### 身份字段校验

外部 UserInfo 必须按配置提供合法 `email`、唯一 `sub` 和布尔型邮箱验证状态。`email_verified_claim` 是 provider 必填项：claim 缺失、类型不是布尔、或取值为 `false` 时拒绝身份解析和自动建号，回跳 `external_error=oauth_email_unverified`。缺少该配置的存量 provider 无法启用，也不会跳转外部 IdP，回跳 `external_error=oauth_provider_not_found`。

首次外部登录在邮箱不存在时创建辰星账号并绑定 `(provider, sub)`；自动建号在同一数据库事务内执行普通注册共用的邮箱域名白名单和别名限制，策略拒绝时返回模糊的 `oauth_login_failed`，且不会留下 `users` 或外部身份半成品。已经绑定的 `(provider, sub)` 登录不因管理员后来收紧注册邮箱策略而失效。如果邮箱已存在，不会自动接管或合并本地账号，而是返回 `oauth_account_link_required` 页面提示。

### React SPA 授权确认 `/oauth/consent`

浏览器授权确认页面调用 `GET /api/v1/oauth/authorize/requests/{request_id}` 查询请求，并以 `POST /api/v1/oauth/authorize/requests/{request_id}` 提交 `decision`（`approve` 或 `deny`）。状态变更需要浏览器 Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。

### `POST /oauth/token`

必须使用表单编码。Client 认证二选一：HTTP Basic `Authorization: Basic base64(client_id:client_secret)`，或表单中的 `client_id` + `client_secret`，不能同时使用。

授权码交换：

```text
grant_type=authorization_code&code=...&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier=...
```

`redirect_uri` 必须与创建该授权码的 `/oauth/authorize` 请求中的原始文本完全一致；即使两个 URL canonicalize 后等价（例如默认 `:443` 或根斜杠差异），不同文本仍返回 `invalid_grant`。

刷新 Token：

```text
grant_type=refresh_token&refresh_token=...
```

刷新请求可用 `scope` 缩小原授权范围；省略或传空白字符串时保留原授权 Scope，不会把权限永久清空。

成功响应 `200`：

```json
{"access_token":"...","token_type":"Bearer","expires_in":604800,"scope":"openid email","refresh_token":"...","id_token":"..."}
```

`refresh_token` 会轮换；包含 `openid` Scope 时返回 `id_token`。授权码和刷新 Token 均为一次性消费。

授权码除 Client 和 Redirect URI 外还绑定签发时的浏览器会话。会话被撤销（用户登出）或过期后，授权码即使仍在 TTL 内也不能兑换，返回 `invalid_grant`；被拒绝的授权码不会被消费，可在会话恢复有效后重试。

授权码已消费、Refresh Token 已暂存后，服务还会复核授权同意版本。若这次最终复核因数据库暂时不可用而返回 `503 temporarily_unavailable`，服务会销毁尚未披露的 Refresh Token，并在确认销毁成功时恢复授权码供同一次交换重试；若无法确认销毁结果，授权码保持已消费，客户端需重新发起授权。两种 503 分支都会保留该授权码对应的套餐退款台账，因此没有成功 `TokenResponse` 的失败不会永久计入日/月授权用量。

Refresh Token 轮换在 successor 已原子写入 Redis 后同样回源复核兑换闸门看到的同意版本和撤销状态。版本变化、撤销、同意缺失或复核存储故障都会先原子回滚未披露的 successor；若 Redis 无法确认回滚状态，则返回 `temporarily_unavailable`，否则按复核结果返回 `invalid_grant` 或 `temporarily_unavailable`。所有失败分支都不会返回 Access Token、ID Token 或新的 Refresh Token；`session_epoch`、Client Secret generation、family 墓碑和审计围栏继续独立生效。

Token 请求按 Client 所属用户的套餐 `max_qps` 做 1 秒滑动窗口限流，超限返回 `429 temporarily_unavailable`；套餐未配置 `max_qps`（`null`）时不限流。

处理超时（见上文「基础约定」）时，`/oauth/token` 与其它 `/oauth/*` 协议端点返回 `503 temporarily_unavailable`（RFC 6749 信封），**不会**返回内部 API 的 `504 request_timeout`。

#### ID Token Claims

`id_token` 是 RS256 签名的 JWT，Header 携带 `kid`；公钥从 `/.well-known/jwks.json` 获取。Payload Claims：

| Claim | 是否总是出现 | 说明 |
| --- | --- | --- |
| `iss` | 是 | 签发者，等于 PostgreSQL `app_settings` 中的运行期 Issuer；旧环境兼容导入后也以该值为准 |
| `sub` | 是 | 用户主体标识符 |
| `aud` | 是 | 接收方 `client_id` |
| `exp` | 是 | 过期时间（Unix 秒） |
| `iat` | 是 | 签发时间（Unix 秒） |
| `auth_time` | 否 | 终端用户完成认证的时刻（会话建立时间，Unix 秒，OIDC Core 1.0 §2）。授权码流程有会话绑定时签发；刷新令牌流程和无会话降级路径**省略该键**，不写 `null` |
| `nonce` | 否 | 授权请求携带 `nonce` 时原样回填（OIDC Core §3.1.3.7） |
| `email` | 否 | Scope 含 `email` 时签发 |
| `name` | 否 | Scope 含 `profile` 且用户设置了显示名称时签发 |

Discovery 的 `claims_supported` 与实际签发保持一致：`sub`、`iss`、`aud`、`exp`、`iat`、`email`、`name`、`nonce`、`auth_time`。`azp` 属于单 audience 场景可省略的 Claim（OIDC Core §2），本服务不签发也不在 `claims_supported` 中声明。

### `GET /oauth/userinfo` / `POST /oauth/userinfo`

GET 使用请求头 `Authorization: Bearer <access_token>`。POST 支持同一 Bearer 请求头，或 `application/x-www-form-urlencoded` 表单字段 `access_token`；两种方式必须二选一，同时提交返回 `400 invalid_request`。

响应字段按 Scope 返回：

```json
{"sub":"1","email":"user@example.com","name":"显示名称"}
```

### `POST /oauth/revoke`

表单字段：`token` 必填，`token_type_hint` 可选（`access_token` 或 `refresh_token`）。Client 认证与 Token 端点一致：HTTP Basic、表单 `client_id` + `client_secret`（`client_secret_post`），或公开 Client 只提交 `client_id` 的 `none`；认证方式不得混用。成功响应 `200` 且无响应体。

## 管理 API

运行期 Issuer 保存在 PostgreSQL `app_settings`，由 Owner 在管理设置中写入并由运行时热更新。数据库尚未设置 Issuer 时是保护模式：`/health*`、静态前端、首 Owner 引导、ID=1 Owner 登录以及未依赖正式 Issuer 的管理路径仍可用；`ADMIN_TOKEN` 是管理 API 的恢复通道。公开注册、普通用户创建、管理员/Owner 创建关闭，只有 OAuth/OIDC、Discovery、JWKS 和外部登录路由由运行时门禁拒绝。不能从请求 Host 推导 Issuer。

管理员 Bearer Token 请求头：`Authorization: Bearer <ADMIN_TOKEN>`。初始化完成后，管理 API 有两条独立通道，任一通过即可继续按角色判定权限：系统 `ADMIN_TOKEN` Bearer（权限等价于 Owner，无用户 ID，豁免浏览器 CSRF），或普通用户 Session。浏览器写操作使用 `__Host-chenxing_session`、`__Host-chenxing_csrf` Cookie 和 `X-CSRF-Token` 三者绑定（loopback HTTP 开发环境使用对应的不带前缀名称）。

`ADMIN_TOKEN` 为空时整个管理面关闭：Bearer 与浏览器 Session 两条通道都被拒绝，已初始化的管理接口统一返回 403 `admin_disabled`。不存在 Owner 时公开的首个 Owner 初始化接口（`POST /api/v1/admin/bootstrap`）不属于这两条通道，无论是否配置 `ADMIN_TOKEN` 都保持公开。

角色为 `user`、`admin`、`owner`，权限按层级继承。管理员登录不再有独立接口、密码表、Session 或 Cookie；所有角色使用 `/api/v1/auth/login`。

### `POST /api/v1/admin/bootstrap`

用于初始化首个 Owner，无需认证，不要求 Issuer 已配置。只有不存在 Owner 时请求才会成功；初始化使用数据库并发锁保证最多创建一个 Owner，成功后不可重复初始化。请求按可信源 IP 限制为每分钟 5 次，缺少可信源地址或 Redis 限流不可用时按配置 fail closed。请求必须包含用户名、邮箱和密码，首个 Owner 的用户 ID 为 `1`，成功后不自动创建 Session。在保护模式下，这是创建首个 Owner 的唯一公开入口。

```json
{"username":"chenxing-owner","email":"owner@example.com","password":"at-least-10-chars"}
```

成功响应包含统一用户 `id`、`username`、`email` 和 `role`，不会自动创建 Session。

### `GET /api/v1/admin/bootstrap/status`

Owner 尚未初始化时公开返回 `{"initialized":false}`，供 Web 前端显示 Owner 初始化界面。实例已有 Owner 后返回与未知路径一致的 `404 not_found`，不再向匿名扫描者确认初始化状态，也不区分 Issuer 未配置、待重载或运行时无效等收敛异常。响应不含 `generation`、`phase`、`issuer_persisted` / `persisted` 等内部状态。Issuer 诊断只通过具备 `manage_issuer` 的 `GET /api/v1/admin/settings/issuer` 返回。数据库故障返回 500。

### `GET/PUT /api/v1/admin/settings/issuer`

Issuer 设置接口仅 Owner（`manage_issuer`）可用。GET 返回 `persisted`、`loaded` 和 `phase`，用于区分数据库事实与当前进程状态。PUT 请求体为 `{"value":"https://auth.example.com","expected_generation":0,"confirm":false}`；Issuer 必须是无凭据、路径、查询和片段的 http(s) 根 URL。`expected_generation` 用于 CAS 并发保护，修改已有值时必须显式传 `confirm:true`。浏览器 Session 写入需要 CSRF；持久化和 `issuer_configure`/`issuer_update` 审计同事务提交，成功后当前进程立即热生效。

### 注册邮件发件地址

管理员 Web 控制台入口为 `/admin-console/login`，会跳转到统一登录页；登录后在“邮件设置”页面维护用户注册流程使用的发件地址。该设置使用普通 Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 保护，只有 Owner 可修改。

- `GET /api/v1/admin/settings/registration-email`：读取当前发件地址，未配置时返回 `{"registration_email_from":null}`。
- `PUT /api/v1/admin/settings/registration-email`：更新发件地址，提交 `{"registration_email_from":"no-reply@example.com"}`；传 `null` 或空字符串可清除配置，成功返回更新后的设置。

发件地址保存于 PostgreSQL 的 `app_settings` 表，不从环境变量、请求 Host 或前端状态推导。发件地址与 SMTP 设置双向镜像：SMTP `from_address` 非空时优先作为注册发件人。

### `GET/PUT /api/v1/admin/settings/smtp`

需要 `ManageSettings`。GET 返回 `host`、`port`、`username`、`from_address`、`ssl_enabled`、`force_auth_login`、`password_configured`。未配置密码时 `password_configured` 为 `false`。响应、日志和审计永不包含 `password` 或 `password_ciphertext`。

PUT 用 `password_action` 表达密码三态，不要再靠空字符串猜测：

- `keep`：保留已存密文；`password` 必须省略或 `null`。
- `set`：加密替换密文；`password` 必须是非空字符串，最长 512 字符。
- `clear`：在同一事务里删除已存密文；`password` 必须省略或 `null`。

省略 `password_action` 只兼容旧客户端：此时省略或 `null` 的 `password` 视为 `keep`，非空 `password` 视为 `set`。空字符串不再等于 `keep`。`keep`/`clear` 携带任何 `password` 值、`set` 缺密码，或空字符串，一律 `400 invalid_smtp_setting`。成功响应与 GET 相同，审计只记录 `password_action` 和 `password_configured`。

`GET /api/v1/admin/settings/passkey`、`GET /api/v1/admin/settings/email-policy` 和 `GET /api/v1/admin/settings/security-limits` 的 JSON body 始终是设置对象本身。若库里的行无法用于安全热路径，响应额外带 `X-Chenxing-Setting-Diagnostic: invalid` 或 `corrupt`，便于管理员保存修复；有效值和未配置行不带该头。头和 body 都不回显损坏 JSON、域名或阈值。

### 用户管理

- `GET /api/v1/admin/users?limit=50&offset=0`：列出用户，需要 `ManageUsers`。响应是用户数组。服务端强制分页：`limit` 默认 `50`，取值被 clamp 到 `[1, 200]`（与审计列表一致），`offset` 默认 `0`，负值按 `0` 处理。需要 `total` 和分页信封时用 `GET /api/v1/admin/users/query`。
- `POST /api/v1/admin/users`：创建用户，提交 `{"username":"alice","email":"alice@example.com","password":"...","display_name":null,"role":"user","status":"active"}`。`display_name`、`role`、`status` 可省略，`role` 缺省 `user`，`status` 缺省 `active`。基线权限 `ManageUsers`；`role` 为 `admin` 或 `owner` 时额外要求 `ManageRoles`。Issuer 未配置的保护模式下该接口关闭并返回 `503 issuer_not_configured`，包括创建普通用户和创建特权用户。正常模式成功 `201`，响应是公开用户字段，不含口令哈希或任何凭据材料。`400` 为 `invalid_role`、`invalid_status`、`invalid_username`、`invalid_email`、`password_too_short`、`password_too_long`、`display_name_too_long`、`email_domain_not_allowed`、`csrf_invalid`；`403` 为 `admin_forbidden`；`409` 为 `username_already_registered`、`email_already_registered`、`owner_bootstrap_required`。
- `POST /api/v1/admin/users/{user_id}/{status}`：设置用户状态，基线需要 `ManageUsers`，目标为 Owner 时额外需要 `ManageRoles`。授权先于资源查询，低权限调用者不能枚举用户或 Owner 身份。状态常用为 `active`、`disabled`；非法状态返回 `400 invalid_status`，用户不存在返回 `404 user_not_found`，成功 `204`。禁止修改自己的状态，自我操作返回 `403 self_status_change_forbidden`。

用户列表元素：`id`、`username`、`email`、`display_name`、`status`、`role`、`created_at`。按 `created_at DESC, id DESC` 排序。

### 认证因子恢复

- `GET /api/v1/admin/users/{user_id}/auth-factors`：查看账号已绑定的因子方法；TOTP 另报 `key_state` / `readable`，不含 kid、密文或种子。需要 `ManageUsers`。
- `DELETE /api/v1/admin/users/{user_id}/auth-factors/totp`：删除 TOTP 因子并撤销该账号全部 Session 与 Refresh Token。需要 Owner 专属的 `ManageAuthFactors`。
- `DELETE /api/v1/admin/users/{user_id}/auth-factors/passkey`：删除该账号全部 Passkey 凭据并撤销全部 Session 与 Refresh Token。需要 `ManageAuthFactors`。Passkey-only 账号下次密码登录直接签发普通 Session，可从安全设置重新绑定；仍绑定 TOTP 的账号保留 TOTP。

末位 Owner 丢失全部 Passkey 时无法再签发管理 Session。这条恢复必须使用系统 `ADMIN_TOKEN` Bearer 通道：它不依赖现有 Passkey 或用户 Session，避免形成「要先有 Passkey 才能恢复 Passkey」的闭环。`ADMIN_TOKEN` 为空时整个管理面关闭，该逃生通道一并不可用。浏览器 Session 写操作仍须携带 Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。Admin 角色返回 `403 admin_forbidden`。账号没有对应因子时返回 `404 totp_factor_not_found` / `passkey_factor_not_found`，且不会推进 `session_epoch`。

Passkey 重置成功响应：

```json
{"user_id":1,"removed":2,"credentials_revoked":true}
```

### 特权用户管理

- `GET /api/v1/admin/admins`：列出角色为 `admin` 或 `owner` 的统一用户，需要 `ManageUsers`。
- `POST /api/v1/admin/admins`：创建完整的特权用户，需要 Owner 权限和普通用户 CSRF；保护模式下返回 `503 issuer_not_configured`。
- `POST /api/v1/admin/users/{user_id}/role`：修改其他用户角色，仅 Owner 可用；禁止自我改角色，降级最后一个活跃 Owner 返回 `409 last_owner_required`。

创建字段：`username`、`email`、`password`、`role`，角色只允许 `admin` 或 `owner`。返回的用户摘要不包含密码或哈希。

### 套餐与权益管理

套餐定义 OAuth Client 数量、日/月授权配额和 QPS 上限；未显式分配套餐或套餐过期的用户回落到默认套餐。

- `GET /api/v1/admin/plans`：列出全部套餐（含已归档），每个元素带 `assigned_users`，需要 `ManageSettings`。
- `POST /api/v1/admin/plans`：创建套餐，提交 `code`、`name`、`description`、`oauth_clients_limit`（0–1000）、`daily_auth_limit`（0–1000000）、`monthly_auth_limit`（0–31000000 或 `null` 表示无限）、`max_qps`（1–10000 或 `null` 表示不限）、`is_default`；`code` 服务端归一化为小写。成功 `201`。越界返回 `400 invalid_plan`。
- `PUT /api/v1/admin/plans/{id}`：更新套餐，字段同创建，成功返回更新后的套餐。
- `POST /api/v1/admin/plans/{id}/archive`：归档套餐；默认套餐不可归档，返回 `409 default_plan_protected`。
- `POST /api/v1/admin/plans/{id}/restore`：恢复套餐。
- `POST /api/v1/admin/users/{user_id}/plan`：为用户分配套餐，提交 `{"plan_id":1,"expires_at":"2026-12-31T00:00:00Z"}`；`expires_at` 传 `null` 或省略表示永久有效，归档套餐不可分配。目标为 Owner 时除 `ManageUsers` 外还需要 `ManageRoles`。

套餐 CRUD（create/update/archive/restore）需要 `ManageSettings` 权限；为普通用户分配套餐需要 `ManageUsers`，为 Owner 分配套餐还需要 `ManageRoles`。两种操作均记录审计事件。

### Client 管理

请求字段：

```json
{"client_name":"我的应用","redirect_uris":["https://app.example/callback"],"scopes":["openid","email"]}
```

Client 的 scopes 由服务端配置的 `OAUTH_CLIENT_ALLOWED_SCOPES` allowlist 约束，默认只允许
`openid`、`profile`、`email`；自定义 scope 必须先加入服务端配置，且授权请求仍必须精确落在该
Client 自身注册的 scope 集合内。

- `POST /api/v1/admin/clients`：创建 Client，需要 `ManageClients`。浏览器 Session 请求必须携带 `X-CSRF-Token`，也可使用有效的 `ADMIN_TOKEN` Bearer 请求而不携带浏览器 CSRF；响应包含 `client_secret`，只返回这一次。
- `GET /api/v1/admin/clients`：列出 Client，不返回 Secret 或其哈希。
- `PUT /api/v1/admin/clients/{client_id}`：更新配置，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/disable`：禁用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/enable`：启用，成功 `204`。
- `POST /api/v1/admin/clients/{client_id}/rotate-secret`：轮换 Secret，成功响应包含新的 `client_id` 和 `client_secret`，只显示新 Secret 一次。

上述 Client 写操作触发套餐 Client 数量上限时返回 `409 quota_exceeded`；数据库或其他内部故障仍返回 500，不再伪装成配额或权限错误。

Client 列表元素包含：`id`、`client_id`、`client_name`、`redirect_uris`、`scopes`、`status`、`owner_user_id`。不返回 Secret 或其哈希。

### 自定义 OAuth 提供商管理

管理界面在 React 控制台的 `/admin/settings`。旧地址 `GET /admin/settings/oauth` 仅 303 转发到 `/admin/settings`（查询串原样保留），旧地址 `GET /admin/login` 仅 303 转发到 `/login`。也可以直接使用以下 API。提供商默认停用，确认配置无误后再启用。

提供商一律按 **OAuth 2.0 + UserInfo** 信任模型接入，摘要中的 `trust_model` 恒为 `oauth2_userinfo`；本平台不为自定义提供商验证 ID Token，也不接受 issuer/JWKS/算法策略配置。详见上文「信任模型：OAuth 2.0 + UserInfo」。

- `POST /api/v1/admin/oauth/providers`：创建提供商。必须填写名称、唯一小写 `slug`、授权/Token/UserInfo 地址、Client ID/Secret、Scopes；Secret 只在请求中出现，服务端使用 `KEY_DIRECTORY/oauth-provider-secret.key` 以 AES-256-GCM 加密保存。
- `GET /api/v1/admin/oauth/providers`：列出提供商摘要，包含 `trust_model`、`callback_uri` 和 `client_secret_configured`，不返回 Secret 或密文。
- `PUT /api/v1/admin/oauth/providers/{slug}`：更新配置；`client_secret` 省略时保留原 Secret。
- `POST /api/v1/admin/oauth/providers/{slug}/enable`、`/disable`：启用或停用。

提供商的授权、Token、UserInfo 地址必须使用 HTTPS，且 IP 字面量和连接时 DNS 解析结果都必须是公网可路由地址；私网、链路本地、CGNAT、ULA、IPv6 站点本地（`fec0::/10`）、文档与保留前缀，以及混合公私网解析均被拒绝。IPv6 侧只放行 `2000::/3` 全局单播中未被 IANA 特殊用途占用的部分，未分配空间默认拒绝。仅 `localhost`、IPv4 loopback 或 `[::1]` 可在显式开启 `OAUTH_PROVIDER_LOOPBACK_ENABLED=true` 后使用 HTTP 进行本机测试（Issue #343）；该开关默认关闭，生产环境必须保持关闭——回环端点会收到解密后的 Client Secret 与用户 Access Token。

校验挂在实际连接使用的 DNS resolver 上，避免先解析后连接造成 DNS rebinding 时间窗。provider 专用 HTTP 客户端显式禁用系统代理：`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 一律不生效，因此上述地址筛查始终作用于真正的连接目标，不依赖运维配置 `NO_PROXY`。需要经代理访问外部 IdP 的部署应使用出网网关，而不是给服务进程设置代理环境变量。

提供商支持 `basic`（Token 请求 HTTP Basic）和 `request_body`（Token 表单）两种 Client 认证方式；Claim 路径支持点分隔对象路径，例如 `profile.email`。浏览器写操作需要普通 CSRF Cookie 与 `X-CSRF-Token`；Bearer Token 是现有自动化兼容方式。

### `GET /api/v1/admin/audit?limit=50`

查询审计事件，需要 `ReadAudit`。`limit` 可选，默认 50。

### `POST /api/v1/admin/keys/rotate`

轮换 RS256 签名密钥，需要 `RotateKeys`。新公钥立即进入 JWKS；签发权仍留在旧
active key，直到 `KEY_ACTIVATION_DELAY_SECONDS`（默认 65，覆盖 JWKS
`max-age=60` 与一次跨实例同步）结束。响应里的 `key_id` 是新发布的密钥，
窗口未到时它还不是当前签名密钥。响应：

```json
{"key_id":"...","published_key_count":2}
```

### `POST /api/v1/admin/keys/{key_id}/revoke`

按 `kid` 紧急撤销签名密钥，需要 `RotateKeys`。普通浏览器 Session 请求必须同时提供
HttpOnly Session Cookie、CSRF Cookie 和匹配的 `X-CSRF-Token`；`ADMIN_TOKEN` Bearer
请求沿用管理 API 的系统令牌语义。撤销 active key 时，服务会在同一密钥存储锁内切换到
仍有效的替代 key；不存在替代 key 时返回 `409`，不会改变密钥状态。成功响应：

```json
{"key_id":"...","active_key_id":"...","published_key_count":1}
```

### 管理后台 UI API

- `GET /api/v1/admin/auth/me`：从普通用户 Session 返回当前管理用户的统一 `user_id`、角色、权限和身份摘要；Bearer Token 自动化请求的 `user_id` 为 `null`。Owner 是最高级角色，拥有全部权限。
- `GET /api/v1/admin/overview`：返回全局用户、OAuth Client、管理员和审计计数。
- `GET /api/v1/admin/users/query?page=1&page_size=20&search=...&status=active`：分页筛选用户，需要 `ManageUsers`。每个 `items` 条目包含当前生效套餐 `plan`（`id`、`code`、`name`、`expires_at`）；未显式挂载套餐或挂载已到期时返回 active 默认套餐，`expires_at: null` 表示永久有效。
- 用户查询响应条目示例：

  ```json
  {
    "id": 42,
    "username": "alice",
    "email": "alice@example.com",
    "display_name": "Alice",
    "status": "active",
    "role": "user",
    "created_at": "2026-08-01T00:00:00Z",
    "plan": {
      "id": 3,
      "code": "pro-max",
      "name": "专业版",
      "expires_at": "2026-09-01T00:00:00Z"
    }
  }
  ```
- `GET /api/v1/admin/clients/query?page=1&page_size=20&search=...&status=active`：分页筛选全局 Client，需要 `ManageClients`，返回 owner ID 但不返回 Secret。
- `GET /api/v1/admin/audit/query?page=1&page_size=20&action=...&resource_type=...`：分页筛选审计，需要 `ReadAudit`。

分页响应统一为 `{"items":[],"page":1,"page_size":20,"total":0}`。`page` 必须是大于等于 1 的整数，`page_size` 必须是 1–100 的整数；格式错误、整数溢出、数值越界或 offset 溢出都返回不含解析细节的 `400 invalid_pagination`，不做静默修正。管理员 API 继续支持 Bearer Token；浏览器 Session 写操作必须使用普通 CSRF Cookie 和 `X-CSRF-Token`。

## 权限矩阵

| 角色 | 用户/管理员 | Client | OAuth 提供商 | 套餐 | 审计 | 密钥轮换 |
| --- | --- | --- | --- | --- | --- | --- |
| `owner` | 是 | 是 | 是 | 是 | 是 | 是 |
| `admin` | 是 | 是 | 是 | 是 | 是 | 否 |
| `user` | 否 | 本人 | 否 | 否 | 否 | 否 |

## 前端接入建议

1. SPA 登录优先调用 `/api/v1/auth/login`，保留响应 Cookie，并将 CSRF Cookie 读取后放入写请求的 `X-CSRF-Token`。
2. OAuth 接入使用 Authorization Code + PKCE S256；`state` 和 `nonce` 必须由接入方生成并校验。
3. Token 交换和撤销必须由受信任后端完成，避免把 Client Secret 放进浏览器代码。
4. 生产环境使用 HTTPS，并确保 `COOKIE_SECURE=true`。
