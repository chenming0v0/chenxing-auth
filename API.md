# 辰星认证中枢 API

本文档以当前后端代码实际暴露的接口为准，供前端和 OAuth/OIDC 接入方使用。

## 基础约定

- Base URL 使用部署后的认证服务地址，例如 `https://auth.example.com`。
- JSON 请求发送 `Content-Type: application/json`；OAuth Token 和 Revocation 请求发送 `application/x-www-form-urlencoded`。
- 时间使用 RFC 3339 字符串；用户、Session、OAuth Client、认证因子、外部身份、提供商和审计事件的数据库内部 ID 是从 1 开始递增的整数。Client ID、提供商 slug、Session Token、授权码等协议或凭据标识仍使用字符串。
- 认证失败、参数错误等 JSON 错误统一为：

```json
{"code":"invalid_credentials","message":"email or password is incorrect"}
```

- 常见状态码：`200` 成功，`201` 创建成功，`204` 成功且无响应体，`400` 参数或业务校验失败，`401` 未认证，`403` 无权限，`409` 冲突，`503` 依赖暂不可用，`500` 服务端错误。
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

当前公开注册在真实的邮件投递和验证令牌消费能力接入前 fail-closed：格式合法的请求返回 `503` 和 `email_verification_unavailable`，不会创建 active 用户，也不会写入无期限的待验证身份。系统不会把邮件标记为已验证，也不会在响应中返回验证令牌。

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

首次登录或已绑定因子但尚未完成验证时响应 `202`，并设置短期 HttpOnly pending-login Cookie：

```json
{"status":"factor_setup_required","methods":["totp","passkey"]}
```

已绑定因子时 `status` 为 `factor_required`，`methods` 只包含当前策略允许的已绑定方式；全局禁用 Passkey 时不会发布 `passkey`。ticket 不再出现在普通 JSON 响应中，而是由 `HttpOnly`、`SameSite=Lax` 的 pending-login Cookie 携带，并绑定同一响应下发的独立 holder Cookie。TOTP 登录可在本请求中携带当前六位 `totp_code`；passkey 使用下面的 WebAuthn challenge 接口。没有可用因子时只能进入策略允许的设置流程。

HTTPS 部署使用 `__Host-chenxing_login_ticket` 和 `__Host-chenxing_login_holder`；仅在 loopback HTTP 本地开发时使用 `chenxing_login_ticket` 和 `chenxing_login_holder`。两个 Cookie 都是 `Path=/`、`HttpOnly`、`SameSite=Lax`，成功签发 Session 后立即清理。

因子完成后响应 `200`：

```json
{"expires_at":"2026-08-04T00:00:00Z"}
```

同时设置 HttpOnly Session Cookie 和 CSRF Cookie。HTTPS 部署使用 `__Host-chenxing_session` 与 `__Host-chenxing_csrf`，它们固定为 `Secure; Path=/` 且不带 `Domain`，由浏览器强制 host-only 约束。仅在 loopback HTTP 本地开发时才允许 `COOKIE_SECURE=false`，此时使用不带前缀的兼容名称。浏览器请求应使用 `credentials: "include"`，再通过 `/api/v1/auth/status` 和 `/api/v1/auth/me` 确认登录状态。默认不会将可直接使用的 Session token 放入 JSON；非浏览器兼容调用只有在服务端 `SESSION_TOKEN_RESPONSE_ENABLED=true` 且显式发送 `X-Chenxing-Session-Mode: token` 时才会收到 `session_id`。

Session 同时有固定的绝对截止时间和可滑动的空闲窗口：`SESSION_TTL_SECONDS` 控制绝对期限，`SESSION_IDLE_TIMEOUT_SECONDS` 控制连续无活动期限。成功认证请求会在空闲窗口过半时更新服务端 `last_seen_at`，但不会改变绝对 `expires_at`；Redis TTL 取两者较早者。每个用户的活跃 Session 数受 `SESSION_MAX_CONCURRENT_SESSIONS` 限制，达到上限时最早的活跃 Session 会被撤销。

### 首次 TOTP 绑定

1. `POST /api/v1/auth/totp/setup`，请求 `{}`（旧客户端可附带 `login_ticket`，但必须与 HttpOnly Cookie 完全一致），响应一次性返回 `secret_base32` 和 `otpauth_url`。前端应使用项目内二维码组件将 `otpauth_url` 作为二维码内容本地生成二维码；`secret_base32` 仅用于无法扫描时手动输入或复制。服务端不调用第三方二维码服务，也不返回二维码图片。
2. `POST /api/v1/auth/totp/setup/confirm`，请求 `{ "code":"123456" }`。验证码正确后保存加密秘钥、消费 ticket 并返回 Session Cookie；错误验证码不会消费 ticket。

已有 TOTP 的待处理登录也可以调用 `POST /api/v1/auth/totp/login`，请求包含当前六位 `code`。验证码正确后消费 ticket 并返回 Session Cookie；无效或缺少 holder proof 的 ticket 返回 `400`，错误验证码返回 `401`。

验证码在同一时间步内只能使用一次，边界按「用户 + 时间步」判定，与走的是绑定确认还是登录验证无关：绑定确认消费掉的验证码不能再用于 `POST /api/v1/auth/totp/login` 或带 `totp_code` 的密码登录，换一张新的 login ticket 也不行，反向同理。命中这种冲突时返回 `401`，ticket 和待确认注册都保留，等下一个验证码重试即可。

### Passkey / WebAuthn

- `POST /api/v1/auth/passkeys/register/start`：请求 `{}`，返回 WebAuthn `PublicKeyCredentialCreationOptions`。
- `POST /api/v1/auth/passkeys/register/finish`：请求浏览器 `navigator.credentials.create()` 返回的 `credential`，验证通过后保存公开凭据并返回 Session Cookie。
- `POST /api/v1/auth/passkeys/authentication/start`：请求 `{}`，返回 `PublicKeyCredentialRequestOptions`。
- `POST /api/v1/auth/passkeys/authentication/finish`：请求浏览器 `navigator.credentials.get()` 返回的 `credential`，验证通过后更新 credential counter、消费 ticket 并返回 Session Cookie。

管理员通过 `PUT /api/v1/admin/settings/passkey` 禁用 Passkey 时，如果存在活跃且唯一绑定 Passkey 的账号，服务端返回 `409 passkey_disable_blocked`，设置不会变更。这样已绑定 Passkey 的账号不会因全局策略被锁定；禁用后新的登录因子响应和首次绑定选项只发布 TOTP。

所有 pending-login Cookie、`login_ticket` 和 WebAuthn challenge 默认有效 5 分钟；ticket 是一次性的。Redis 中只保存 holder Cookie 的摘要，不保存 holder 原值；缺少 holder、Cookie 中 ticket 与旧请求字段不一致、或升级前无 holder 摘要的 ticket 都 fail closed，需要重新开始登录。WebAuthn 的 RP ID 和 origin 由固定配置 `WEBAUTHN_RP_ID`、`WEBAUTHN_ORIGIN` 控制，不能从请求 Host 推导。

浏览器 OAuth 登录现在由 React SPA 承接。密码步骤调用 `POST /api/v1/auth/login`，TOTP 绑定和登录分别调用 `POST /api/v1/auth/totp/setup`、`POST /api/v1/auth/totp/setup/confirm` 或 `POST /api/v1/auth/totp/login`；passkey 流程使用上面的 WebAuthn API。因子完成后，SPA 调用授权请求绑定接口并继续授权确认。

### `DELETE /api/v1/auth/session`

撤销当前用户 Session，响应 `204` 并清理 Cookie。身份只从 HttpOnly Session Cookie 读取，`X-Chenxing-Session` 请求头不再被该端点接受。

撤销是状态变更，必须无条件同时发送：

- Session HttpOnly Cookie
- CSRF Cookie
- `X-CSRF-Token`，且值与 CSRF Cookie 和 Session 内 Token 一致

### 用户中心 UI API

- `GET /api/v1/auth/status`：返回当前是否登录。
- `GET /api/v1/auth/me`：返回当前用户资料和当前 Session 到期时间。
- `PATCH /api/v1/auth/me`：更新 `display_name`，需要用户 CSRF。
- `POST /api/v1/auth/password`：校验当前密码并修改密码，成功返回 `204`，同时撤销该用户所有 Session。
- `GET /api/v1/auth/entitlements`：返回当前生效套餐摘要（`code`、`name`、`description`、`validity`）和各项权益用量；`limit` 为 `null` 表示无限，缺失表示数值无上限概念（如 QPS）。
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

### `GET /oauth/authorize`

授权码入口，成功后重定向到注册的 `redirect_uri`，附带 `code` 和原始 `state`。

必填查询参数：

| 参数 | 说明 |
| --- | --- |
| `client_id` | 已注册 Client ID |
| `redirect_uri` | 必须精确匹配注册值 |
| `response_type` | 当前仅支持 `code` |
| `scope` | 空格分隔，如 `openid email profile`；每个值必须同时属于服务端 allowlist（默认 `openid`、`profile`、`email`）和该 Client 已注册的 scopes |
| `state` | 必填，建议由接入方随机生成，最多 512 个字符 |
| `code_challenge` | PKCE challenge |
| `code_challenge_method` | 必须为 `S256` |
| `nonce` | 使用 OIDC 时建议必填并随机生成，最多 512 个字符 |

未登录的浏览器请求会重定向到 React SPA 的 `/login?request_id=...`；已登录但尚未授权该 scope 组合的请求进入 `/oauth/consent?request_id=...`。两条交给 SPA 的路径都会下发 `chenxing_authz_holder` HttpOnly Cookie（防御 OAuth login CSRF，见下文 bind 端点说明）。非 HTML 请求返回 `401 login_required`。

### `POST /api/v1/oauth/authorize/requests/{request_id}/bind`

将当前浏览器 Session 绑定到 pending 授权请求。绑定完成后才能调用 inspect（GET）和 decide（POST）。

调用方必须同时提供：

| 凭据 | 来源 | 说明 |
| --- | --- | --- |
| Session Cookie `__Host-chenxing_session` | TOTP / 密码登录响应 | 身份认证 |
| CSRF Cookie `__Host-chenxing_csrf` + `X-CSRF-Token` | 同上 | 防 CSRF |
| 持有者 Cookie `chenxing_authz_holder` | `/oauth/authorize` 重定向响应 | **防 OAuth login CSRF（#115）** |

**`chenxing_authz_holder` Cookie 说明**：`request_id` 通过 URL 查询参数传递，可能通过 Referer、浏览器历史或分享链接泄露。没有持有者绑定，任何拿到 `request_id` 的已登录攻击者都可以把受害者的 pending 请求绑到自己的会话上并批准，使受害者登录进攻击者账号（OAuth login CSRF / 请求固定攻击）。

`/oauth/authorize` 在把浏览器交给 SPA 时下发该 Cookie（`HttpOnly; SameSite=Lax; Path=/`），其 SHA-256 摘要存入 Redis。bind 端点比对 Cookie 值与摘要，不匹配返回 `403 authorization_holder_invalid`。

升级前创建的旧 pending 记录无摘要，绑定时被拒绝（fail-secure），用户需重新发起授权流程。

**受控重绑（#270）**：上述三项校验全部通过时，无论该 pending 请求此前绑定的是哪个 Session 摘要，都会被重绑到调用者当前的 Session，写入走 CAS 保证原子性。持有者 Cookie 才是所有权凭据，Session 绑定是派生状态，因此重绑不放宽任何安全边界——没有持有者 Cookie 的第三方即使持有有效 Session 仍然被拒（`403`）。这让「会话过期后重新登录继续授权」和「切换账号继续授权」可以自愈；旧行为固定返回 `401 invalid_session`，前端跟着在登录页与授权确认页之间形成跳转循环。授权码在最终 approve 时按当时持有的 Session 签发。重绑记录审计事件 `authorization_request_rebound`。

幂等：同一 Session + 同一持有者 Cookie 重复调用返回 `204`，载荷不变。持续并发修改导致 CAS 无法收敛时返回 `409 authorization_request_conflict`，重试即可。

### `GET /api/v1/oauth/authorize/requests/{request_id}` / `POST ...`

供 JSON 授权确认 UI 使用。请求必须绑定当前浏览器 Session；GET 返回 Client 名称、Redirect 主机、Scope 和剩余有效时间。POST JSON 请求为 `{"decision":"approve"}` 或 `{"decision":"deny"}`，需要用户 CSRF，成功返回经过校验的 `redirect_to`，请求被一次性消费。普通用户项目超过日/月配额时返回 `429 oauth_quota_exceeded`；标准 `/oauth/authorize` 流程返回协议安全的 `temporarily_unavailable` 重定向。

### React SPA 浏览器登录 `/login`

浏览器登录页面由 React SPA 提供。登录请求统一使用 `POST /api/v1/auth/login`；页面通过 `GET /api/v1/auth/external-providers` 查询并显示已启用的自定义 OAuth 提供商。

### `GET /auth/external/{slug}` / `GET /auth/external/{slug}/callback`

开始并完成自定义外部 **OAuth 2.0** 登录。`slug` 来自管理员设置；开始请求可携带 `request_id` 以便登录后继续辰星的授权确认。系统使用一次性 Redis `state` 和 HttpOnly Cookie 绑定浏览器流程，回调成功后创建辰星 Session。

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

首次外部登录在邮箱不存在时创建辰星账号并绑定 `(provider, sub)`；如果邮箱已存在，不会自动接管或合并本地账号，而是返回 `oauth_account_link_required` 页面提示。

### React SPA 授权确认 `/oauth/consent`

浏览器授权确认页面调用 `GET /api/v1/oauth/authorize/requests/{request_id}` 查询请求，并以 `POST /api/v1/oauth/authorize/requests/{request_id}` 提交 `decision`（`approve` 或 `deny`）。状态变更需要浏览器 Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。

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

刷新请求可用 `scope` 缩小原授权范围；省略或传空白字符串时保留原授权 Scope，不会把权限永久清空。

成功响应 `200`：

```json
{"access_token":"...","token_type":"Bearer","expires_in":604800,"scope":"openid email","refresh_token":"...","id_token":"..."}
```

`refresh_token` 会轮换；包含 `openid` Scope 时返回 `id_token`。授权码和刷新 Token 均为一次性消费。

授权码除 Client 和 Redirect URI 外还绑定签发时的浏览器会话。会话被撤销（用户登出）或过期后，授权码即使仍在 TTL 内也不能兑换，返回 `invalid_grant`；被拒绝的授权码不会被消费，可在会话恢复有效后重试。

Token 请求按 Client 所属用户的套餐 `max_qps` 做 1 秒滑动窗口限流，超限返回 `429 temporarily_unavailable`；套餐未配置 `max_qps`（`null`）时不限流。

#### ID Token Claims

`id_token` 是 RS256 签名的 JWT，Header 携带 `kid`；公钥从 `/.well-known/jwks.json` 获取。Payload Claims：

| Claim | 是否总是出现 | 说明 |
| --- | --- | --- |
| `iss` | 是 | 签发者，等于 `APP_ISSUER` 配置值 |
| `sub` | 是 | 用户主体标识符 |
| `aud` | 是 | 接收方 `client_id` |
| `exp` | 是 | 过期时间（Unix 秒） |
| `iat` | 是 | 签发时间（Unix 秒） |
| `auth_time` | 否 | 终端用户完成认证的时刻（会话建立时间，Unix 秒，OIDC Core 1.0 §2）。授权码流程有会话绑定时签发；刷新令牌流程和无会话降级路径**省略该键**，不写 `null` |
| `nonce` | 否 | 授权请求携带 `nonce` 时原样回填（OIDC Core §3.1.3.7） |
| `email` | 否 | Scope 含 `email` 时签发 |
| `name` | 否 | Scope 含 `profile` 且用户设置了显示名称时签发 |

Discovery 的 `claims_supported` 与实际签发保持一致：`sub`、`iss`、`aud`、`exp`、`iat`、`email`、`name`、`nonce`、`auth_time`。`azp` 属于单 audience 场景可省略的 Claim（OIDC Core §2），本服务不签发也不在 `claims_supported` 中声明。

### `GET /oauth/userinfo`

请求头：`Authorization: Bearer <access_token>`。

响应字段按 Scope 返回：

```json
{"sub":"1","email":"user@example.com","name":"显示名称"}
```

### `POST /oauth/revoke`

表单字段：`token` 必填，`token_type_hint` 可选（`access_token` 或 `refresh_token`），并使用同 Token 端点的 Client 认证方式。成功响应 `200` 且无响应体。

## 管理 API

管理员 Bearer Token 请求头：`Authorization: Bearer <ADMIN_TOKEN>`。初始化完成后，管理 API 有两条独立通道，任一通过即可继续按角色判定权限：系统 `ADMIN_TOKEN` Bearer（权限等价于 Owner，无用户 ID，豁免浏览器 CSRF），或普通用户 Session。浏览器写操作使用 `__Host-chenxing_session`、`__Host-chenxing_csrf` Cookie 和 `X-CSRF-Token` 三者绑定（loopback HTTP 开发环境使用对应的不带前缀名称）。

`ADMIN_TOKEN` 为空时只关闭 Bearer 通道：所有 Bearer Token 管理请求被拒绝，而已认证、角色足够且 CSRF 绑定有效的浏览器管理 Session 不受影响，管理 API 仍然可用。不存在 Owner 时公开的首个 Owner 初始化接口（`POST /api/v1/admin/bootstrap`）不属于这两条通道，无论是否配置 `ADMIN_TOKEN` 都保持公开。

角色为 `user`、`admin`、`owner`，权限按层级继承。管理员登录不再有独立接口、密码表、Session 或 Cookie；所有角色使用 `/api/v1/auth/login`。

### `POST /api/v1/admin/bootstrap`

仅用于初始化首个 Owner，无需认证。只有不存在 Owner 时请求才会成功；初始化使用数据库并发锁保证最多创建一个 Owner，成功后不可重复初始化。请求按可信源 IP 限制为每分钟 5 次，缺少可信源地址或 Redis 限流不可用时按配置 fail closed。请求必须包含用户名、邮箱和密码，首个 Owner 的用户 ID 为 `1`，成功后不自动创建 Session。

```json
{"username":"chenxing-owner","email":"owner@example.com","password":"at-least-10-chars"}
```

成功响应包含统一用户 `id`、`username`、`email` 和 `role`，不会自动创建 Session。

### `GET /api/v1/admin/bootstrap/status`

仅未初始化时公开返回 `{"initialized":false}`，供 Web 前端显示 Owner 初始化界面。实例已有 Owner 后返回与未知路径一致的 `404 not_found`，不再向匿名扫描者确认初始化状态；数据库故障返回 500。

### 注册邮件发件地址

管理员 Web 控制台入口为 `/admin-console/login`，会跳转到统一登录页；登录后在“邮件设置”页面维护用户注册流程使用的发件地址。该设置使用普通 Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 保护，只有 Owner 可修改。

- `GET /api/v1/admin/settings/registration-email`：读取当前发件地址，未配置时返回 `{"registration_email_from":null}`。
- `PUT /api/v1/admin/settings/registration-email`：更新发件地址，提交 `{"registration_email_from":"no-reply@example.com"}`；传 `null` 或空字符串可清除配置，成功返回更新后的设置。

发件地址保存于 PostgreSQL 的 `app_settings` 表，不从环境变量、请求 Host 或前端状态推导。当前设置资源只保存地址本身；SMTP 连接参数、发送凭据和邮件模板属于后续邮件服务接入边界。

### 用户管理

- `GET /api/v1/admin/users?limit=50&offset=0`：列出用户，需要 `ManageUsers`。响应是用户数组。服务端强制分页：`limit` 默认 `50`，取值被 clamp 到 `[1, 200]`（与审计列表一致），`offset` 默认 `0`，负值按 `0` 处理。需要 `total` 和分页信封时用 `GET /api/v1/admin/users/query`。
- `POST /api/v1/admin/users`：创建用户，提交 `{"username":"alice","email":"alice@example.com","password":"...","display_name":null,"role":"user","status":"active"}`。`display_name`、`role`、`status` 可省略，`role` 缺省 `user`，`status` 缺省 `active`。基线权限 `ManageUsers`；`role` 为 `admin` 或 `owner` 时额外要求 `ManageRoles`。成功 `201`，响应是公开用户字段，不含口令哈希或任何凭据材料。`400` 为 `invalid_role`、`invalid_status`、`invalid_username`、`invalid_email`、`password_too_short`、`password_too_long`、`display_name_too_long`、`email_domain_not_allowed`、`csrf_invalid`；`403` 为 `admin_forbidden`；`409` 为 `username_already_registered`、`email_already_registered`、`owner_bootstrap_required`。
- `POST /api/v1/admin/users/{user_id}/{status}`：设置用户状态，基线需要 `ManageUsers`，目标为 Owner 时额外需要 `ManageRoles`。授权先于资源查询，低权限调用者不能枚举用户或 Owner 身份。状态常用为 `active`、`disabled`；非法状态返回 `400 invalid_status`，用户不存在返回 `404 user_not_found`，成功 `204`。

用户列表元素：`id`、`username`、`email`、`display_name`、`status`、`role`、`created_at`。按 `created_at DESC, id DESC` 排序。

### 特权用户管理

- `GET /api/v1/admin/admins`：列出角色为 `admin` 或 `owner` 的统一用户，需要 `ManageUsers`。
- `POST /api/v1/admin/admins`：创建完整的特权用户，需要 Owner 权限和普通用户 CSRF。
- `POST /api/v1/admin/users/{user_id}/role`：修改其他用户角色，仅 Owner 可用；禁止自我改角色，降级最后一个活跃 Owner 返回 `409 last_owner_required`。

创建字段：`username`、`email`、`password`、`role`，角色只允许 `admin` 或 `owner`。返回的用户摘要不包含密码或哈希。

### 套餐与权益管理

套餐定义 OAuth Client 数量、日/月授权配额和 QPS 上限；未显式分配套餐或套餐过期的用户回落到默认套餐。

- `GET /api/v1/admin/plans`：列出全部套餐（含已归档），每个元素带 `assigned_users`，需要 `ManageSettings`。
- `POST /api/v1/admin/plans`：创建套餐，提交 `code`、`name`、`description`、`oauth_clients_limit`、`daily_auth_limit`、`monthly_auth_limit`、`max_qps`、`is_default`；`code` 服务端归一化为小写。成功 `201`。
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

管理界面在 React 控制台的 `/console/settings`（原 `GET /admin/settings/oauth` 仅转发到该页面），也可以直接使用以下 API。提供商默认停用，确认配置无误后再启用。

提供商一律按 **OAuth 2.0 + UserInfo** 信任模型接入，摘要中的 `trust_model` 恒为 `oauth2_userinfo`；本平台不为自定义提供商验证 ID Token，也不接受 issuer/JWKS/算法策略配置。详见上文「信任模型：OAuth 2.0 + UserInfo」。

- `POST /api/v1/admin/oauth/providers`：创建提供商。必须填写名称、唯一小写 `slug`、授权/Token/UserInfo 地址、Client ID/Secret、Scopes；Secret 只在请求中出现，服务端使用 `KEY_DIRECTORY/oauth-provider-secret.key` 以 AES-256-GCM 加密保存。
- `GET /api/v1/admin/oauth/providers`：列出提供商摘要，包含 `trust_model`、`callback_uri` 和 `client_secret_configured`，不返回 Secret 或密文。
- `PUT /api/v1/admin/oauth/providers/{slug}`：更新配置；`client_secret` 省略时保留原 Secret。
- `POST /api/v1/admin/oauth/providers/{slug}/enable`、`/disable`：启用或停用。

提供商的授权、Token、UserInfo 地址必须使用 HTTPS，且 IP 字面量和连接时 DNS 解析结果都必须是公网可路由地址；私网、链路本地、CGNAT、ULA、IPv6 站点本地（`fec0::/10`）、文档与保留前缀，以及混合公私网解析均被拒绝。IPv6 侧只放行 `2000::/3` 全局单播中未被 IANA 特殊用途占用的部分，未分配空间默认拒绝。仅 `localhost`、IPv4 loopback 或 `[::1]` 可使用 HTTP 进行本机测试。

校验挂在实际连接使用的 DNS resolver 上，避免先解析后连接造成 DNS rebinding 时间窗。provider 专用 HTTP 客户端显式禁用系统代理：`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 一律不生效，因此上述地址筛查始终作用于真正的连接目标，不依赖运维配置 `NO_PROXY`。需要经代理访问外部 IdP 的部署应使用出网网关，而不是给服务进程设置代理环境变量。

提供商支持 `basic`（Token 请求 HTTP Basic）和 `request_body`（Token 表单）两种 Client 认证方式；Claim 路径支持点分隔对象路径，例如 `profile.email`。浏览器写操作需要普通 CSRF Cookie 与 `X-CSRF-Token`；Bearer Token 是现有自动化兼容方式。

### `GET /api/v1/admin/audit?limit=50`

查询审计事件，需要 `ReadAudit`。`limit` 可选，默认 50。

### `POST /api/v1/admin/keys/rotate`

轮换 RS256 签名密钥，需要 `RotateKeys`。响应：

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

分页响应统一为 `{"items":[],"page":1,"page_size":20,"total":0}`。管理员 API 继续支持 Bearer Token；浏览器 Session 写操作必须使用普通 CSRF Cookie 和 `X-CSRF-Token`。

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
