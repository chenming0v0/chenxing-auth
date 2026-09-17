# Account Provider v1 — 冻结线上契约

状态：**PLANNED**。本文档是协议正本；`snapshot.schema.json` 是快照根的机器可读约束。任何实现必须与本文逐字一致，改动需先改本文并同步夹具。

## 0. 命名与合规声明

- 协议名：`account-provider/v1`。
- 本协议**不是** OAuth 2.0 / OIDC / SCIM，**不**实现 password grant。
- RFC 9700 §2.4 规定资源所有者密码凭据授权 **MUST NOT** 使用；本协议不声称满足该标准，而是明确的自研「受信任门户凭据委托」。参考：<https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4>
- 本协议**不**声称与 provider-hosted Authorization Code + PKCE 具等价安全性。用户在辰星门户输入的提供方凭据会**瞬时**经过辰星；凭据本身**并非**只读，能读写该账号的完整凭据都可能被提交，本协议只保证新签发的授权是只读 `account:read`。残余信任与 ROPC 同类，被显式接受。

## 1. 方向、部署前置与配置

**方向**：本协议由**提供方（provider）**实现并托管，CLtermux 是首个提供方实现。**辰星通行证是消费方/客户端**：用户在**辰星门户**输入提供方凭据，辰星以 HTTP Basic 把凭据送到提供方的只读校验流程，由**提供方**签发令牌与快照。提供方**不**新增任何托管登录 UI。

提供方侧只需 3 个必需环境变量：

- `ACCOUNT_PROVIDER_ISSUER`：该提供方对外可达的规范 HTTPS origin（形如 `https://provider.example.com`，无尾斜杠、无路径、无 query/fragment）。用于元数据、issuer 字段与全部端点基址。**这是提供方的 origin，不是辰星的 OIDC `APP_ISSUER`**；辰星既有移动 OIDC issuer 完全不变。
- `ACCOUNT_PROVIDER_CLIENT_ID` / `ACCOUNT_PROVIDER_CLIENT_SECRET`：运营商注册的机密门户客户端；secret ≥32 随机字节，**绝不复用**旧应用 HS256 secret。

约束：

- **不**存在额外的标签环境变量。元数据 `credentials` 标签由提供方实现自行定义；通用规范允许任意安全标签，单值 ≤128 UTF-8 字节。
- 辰星作为消费方，由管理员在后台保存 `base_url`，其值必须与提供方 issuer origin 一致；端点路径固定。
- **正常的 HTTPS 反向代理部署是被支持的**。禁止的是**出站重定向**（客户端不跟随 3xx 到其他 origin/路径），以及从请求 `Host`/`X-Forwarded-*` 推导 issuer。反代本身不是问题，代理注入的元数据不能决定 issuer。
- **配置缺失时**：新端点一律返回 `503 provider_unavailable`，提供方旧服务不受影响。

## 2. 公开元数据

`GET /.well-known/account-provider`（匿名，无需认证；提供方托管）

```json
{
  "protocol": "account-provider/v1",
  "issuer": "https://provider.example.com",
  "capabilities": ["account:read"],
  "credentials": {
    "identifier_label": "账户",
    "secret_label": "密码",
    "identifier_sensitive": true
  }
}
```

约束：

- `credentials` 是**固定 3 个描述键**的对象：`identifier_label`、`secret_label`、`identifier_sensitive`；输入恰好**2 个字段**：`identifier` 与 `secret`。标签可由提供方实现自定义（CLtermux 用「卡密账号」「卡密密码」，`identifier_sensitive: true`）。
- 无动态 HTML、无表单、无脚本、无模板。
- **不**返回任何令牌、密钥、绑定、账号或私有数据。
- 成功与错误响应均 `Cache-Control: no-store`。

## 3. 端点总览（提供方托管）

| 方法 | 路径 | 认证 | 作用 |
| --- | --- | --- | --- |
| GET | `/.well-known/account-provider` | 匿名 | 元数据 |
| POST | `/api/v1/account-provider/link-sessions` | HTTP Basic | 创建绑定，返回令牌包 + 快照 |
| POST | `/api/v1/account-provider/link-sessions/refresh` | HTTP Basic | 刷新轮换，返回令牌包 + 快照 |
| GET | `/api/v1/account-provider/account` | Bearer | 读取绑定账号快照 |
| POST | `/api/v1/account-provider/link-sessions/revoke` | HTTP Basic | 撤销绑定，幂等 |

通用：

- 所有会话变更请求必须 `Content-Type: application/json`。
- `Idempotency-Key` 头为 **UUID**，在创建与刷新上**必填**。
- 请求体上限 **8 KiB**，响应体上限 **128 KiB**（超限 400 / 服务端自身超限按 5xx 处理）。
- 默认 `connect` 超时 2s、总超时 5s（消费方调用提供方时）。
- 成功与错误响应均带 `Cache-Control: no-store`。
- 响应**不得**包含 SQL、堆栈、内部网络信息或提供方原始错误。

## 4. 认证

### 4.1 Basic（创建/刷新/撤销）

```
Authorization: Basic base64(client_id + ":" + client_secret)
```

- 客户端为运营商注册的机密门户客户端；`client_id` 全程显式绑定到令牌与绑定记录。
- `client_secret` 失败返回 `401 invalid_client`。
- 旧应用 HS256 secret 不得作为客户端密钥。

### 4.2 Bearer（查询）

```
Authorization: Bearer <access_token>
```

- 仅接受本协议签发的 access token；**不**接受任何旧 App / 管理 / Agent API 的令牌。
- 令牌缺失、格式错误或无效一律返回 `401 invalid_access_token`。

## 5. 创建绑定

`POST /api/v1/account-provider/link-sessions`

请求头：`Authorization: Basic ...`、`Idempotency-Key: <UUID>`。

```json
{
  "client_binding_id": "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f",
  "credentials": {
    "identifier": "pub-example-0001",
    "secret": "priv-example-0001"
  }
}
```

规则：

- `client_binding_id`：**随机 UUID**，永不复用；由消费方生成并提交，提供方不得接受浏览器传来的 `uid`。
- `credentials.identifier` 与 `credentials.secret`：各自 ≤255 字节、非空。
- 凭据只用于**一次只读校验**；**绝不**触发提供方旧 `Login`、设备绑定、首登赠送订阅或旧 Session 写入。
- **请求指纹**：`request_fingerprint = HMAC-SHA256(key = 派生自门户 client_secret 的 purpose 分离密钥, msg = 规范化请求)`。提供方**只有**在凭据只读校验通过后才提交 operation 行，且**只**持久化该 keyed 指纹用于操作匹配；**绝不**持久化原始凭据，也**绝不**持久化对可能很弱凭据的**非密钥哈希**（离线爆破风险）。原始凭据不写日志。
- 幂等匹配：
  - 同 `Idempotency-Key` + 同指纹 + 已提交/提交中 → `409 issuance_already_committed`（fail-closed；提供方只存哈希，无法重放 raw token）。
  - 同 `Idempotency-Key` + 不同载荷 → `409 binding_conflict`。
  - 已存在的 `client_binding_id` 被不同操作复用 → `409 binding_conflict`。
  - 已 tombstone 的引用 → 拒绝（`409 binding_conflict`）。
- **短数据库边界、零竞态**：校验与提交分属明确的两步，提交在单条短事务内以 `Idempotency-Key` 唯一约束落定；并发同操作只可能一个成功，其余得到上述明确 409。
- **丢失创建响应**：消费方**不得**用新操作 ID 盲目重试凭据。清理路径是：以新的 `Idempotency-Key` 对同一 `client_binding_id` 发 `revoke`（幂等 204），再用**新的** `client_binding_id` 重连。

成功：`201`，返回**令牌包**（见第 8 节）**且**携带 `snapshot`。

## 6. 刷新

`POST /api/v1/account-provider/link-sessions/refresh`

请求头：`Authorization: Basic ...`、`Idempotency-Key: <UUID>`。

```json
{
  "client_binding_id": "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f",
  "refresh_token": "cxap_rt_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"
}
```

规则：

- **先做安全前置校验，再原子消费**：绑定存在、客户端匹配、账号可用、未过期。前置校验通过后才消费 refresh token。
- 并发同操作（同 `Idempotency-Key` 且同 `refresh_token`）：后到者 `409 refresh_already_committed`，**不**撤销已产出的新一代令牌。
- 不同操作重放：`401 invalid_refresh_token`，fail-closed。
- 刷新成功后：`grant_id` / `client_binding_id` / `uid` / `issuer` **保持不变**；`grant_expires_at` **不**重算；v1 明确**旧 access token 在成功刷新后立即失效**（用于约束存储）。refresh token 轮换为新一代。
- **歧义响应重试（网络错误 / 5xx / 超时）**：使用**同一操作 ID**（同 `Idempotency-Key`）与**同一 `refresh_token`** 重试，以发现已提交结果或得到 `409 refresh_already_committed`。每个合法认证请求本就携带原始令牌，这不是被禁止的「丢失 raw token 重放」。禁止的是：用**新**操作 ID 盲重试、或试图恢复旧一代令牌。
- 若提供方已提交但消费方丢失了令牌包：只能**显式重新授权**并清理，**不**做透明恢复。

成功：`200`，返回与创建**同形状**的令牌包 + `snapshot`（`fetched_at` 反映本次来源新鲜度）。

## 7. 查询账号与撤销

### 7.1 `GET /api/v1/account-provider/account`

- `Authorization: Bearer <access_token>`。
- **无**任意 `uid` 参数；只返回令牌所绑定账号的快照。
- 成功 `200`，body 即 `snapshot.schema.json` 根对象。

### 7.2 `POST /api/v1/account-provider/link-sessions/revoke`

```json
{ "client_binding_id": "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f" }
```

- 成功 `204`，**幂等**。
- 单条事务内**写入 tombstone 并使其 grant 令牌失效**；即使该引用从未成功创建，tombstone 也阻止延迟到达的创建。延迟到达的创建/刷新**不能**复活同一引用；重连必须用新的 `client_binding_id`。
- 提供方**不**为远端重试入队任务：本地撤销即时生效，消费方（辰星）自行负责本地 unlink 与远端撤销 outbox。
- 作用域仅限自己的门户客户端。

## 8. 令牌包、令牌存储边界与生命周期

创建与刷新返回**同形状**：

```json
{
  "protocol": "account-provider/v1",
  "issuer": "https://provider.example.com",
  "grant_id": "9f0c2b7e-3d41-4a88-b1c2-7e6f5d4c3b2a",
  "client_binding_id": "5c1f9c3a-0a1b-4c2d-9e3f-1a2b3c4d5e6f",
  "uid": "acct-1001",
  "scope": "account:read",
  "token_type": "Bearer",
  "access_token": "cxap_at_AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
  "expires_in": 900,
  "refresh_token": "cxap_rt_AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
  "refresh_expires_at": "2026-10-18T00:00:00Z",
  "grant_expires_at": "2026-12-17T00:00:00Z",
  "snapshot": { "...": "见 snapshot.schema.json" }
}
```

- `access_token`：≥256 bit 随机，带类型前缀（`cxap_at_`）。（`cxap_` 是协议级前缀，不含产品分支语义。）
- `refresh_token`：≥256 bit 随机，带类型前缀（`cxap_rt_`）。
- **生命周期（不可续期）**：
  - `grant_expires_at` = 授权**首次创建时间 + 90 天**，刷新时**不重算**、不可延长。
  - `expires_in` 基线 `900`，被 `grant_expires_at` 绝对上限**封顶**（剩余不足 900s 时按剩余）。
  - `refresh_expires_at` = `min(now + 30 days, grant_expires_at)`，RFC3339 UTC；每次刷新按当时 now 计算，但绝不突破 grant 绝对值。
- **存储边界（两侧不同，不得混说）**：
  - **提供方（CL）**：只存 access/refresh 的 SHA256 哈希，无 raw 恢复路径——它是令牌的签发与校验方。
  - **消费方（辰星）**：为了**使用**令牌（以 Bearer 调 `/account`），必须存**可逆的加密令牌包**，AAD = `providerUUID + bindingID + purpose`；这是消费方唯一的密文持有方。
  - **原始凭据**（identifier/secret）：**本协议不为请求中的凭据新增任何持久化副本或日志**。提供方（CL）既有卡密数据库仍是凭据权威存储，**保持原样、不被本协议触碰**；本协议不要求也不允许删除既有 key/卡密字段。短暂的原始凭据中转暴露被显式承认。

## 9. 快照根

字段与约束以 `snapshot.schema.json` 为准，摘要：

| 字段 | 类型 | 约束 |
| --- | --- | --- |
| `schema_version` | string | 固定 `"1"` |
| `issuer` | string | 与提供方配置 issuer 一致 |
| `uid` | string | ≤255 |
| `account` | string | ≤128，非空、非敏感展示账号 |
| `name` | string \| null | ≤128；没有真实姓名来源时 `null` |
| `status` | enum | `active` / `disabled` / `unknown` |
| `subscription` | tagged union | 见下 |
| `fields` | array | ≤64，key 运行时必须唯一 |
| `fetched_at` | RFC3339 | 来源新鲜度 |

`subscription.kind`（已知取值）：

- `"expires_at"` + `expires_at`（RFC3339）
- `"remaining"` + `remaining_seconds`（非负整数**秒**）+ `as_of`（RFC3339）
- `"permanent"`
- `"none"`（省略任何到期字段，不得写 `expires_at: null`）
- `"unknown"`

变体互斥：每个变体在允许真正未知附加属性的同时，**拒绝其他已知变体的字段**（`required` 只看键是否存在，因此 `expires_at: null` 同样被拒）——
`expires_at` 拒绝 `remaining_seconds`/`as_of`；`remaining` 拒绝 `expires_at`；`permanent`/`none`/`unknown` 拒绝 `expires_at`/`remaining_seconds`/`as_of`（含 null）。

语义硬约束：

- `null` **永不**表示永久；`0` **不**表示未知（`remaining_seconds: 0` 就是到期）。
- **超出上表的 `subscription.kind` 是无效快照**：消费方 MUST fail closed 或标记 `stale`，绝不得解释为 `permanent` / `none`。
- `fields[]`：`key` ≤128 字节且**运行时唯一**；`label` ≤256 字节；`type` ∈ `text`(≤512 字节) / `number`(有限安全 JSON number) / `boolean` / `status`(≤64) / `datetime`(RFC3339) / `duration`(非负安全整数**秒**) / `url`(HTTPS、无 userinfo、≤2048)。
- `snapshot.schema.json` **无法**内在地强制 key 唯一，也**无法**按 UTF-8 字节执行上限（`maxLength` 计码点）；实现 MUST 在运行时执行这两项。
- 消费方遇**未知 `type` 必须忽略**，不得按对象渲染；v1 提供方只产出已知取值。
- 无 HTML/JS/CSS/模板；v1 **不**自动加载远程媒体。
- 消费方遇**未知顶层字段必须忽略**（前向兼容）。
- **不**提供任何非标准业务 schema 的行业保证。

## 10. 错误信封

```json
{
  "error": {
    "code": "credential_invalid",
    "message": "credentials rejected",
    "retryable": false,
    "request_id": "b6b9a1e2-6f0a-4d2f-8f7c-1c2d3e4f5a6b"
  }
}
```

| HTTP | code | retryable | 说明 |
| --- | --- | --- | --- |
| 400 | `invalid_request` | false | 结构/参数非法 |
| 401 | `invalid_client` | false | Basic 客户端认证失败 |
| 401 | `invalid_access_token` | false | Bearer 缺失/无效 |
| 401 | `invalid_refresh_token` | false | 刷新令牌无效/已消费且非并发同操作 |
| 403 | `account_disabled` | false | 凭据有效但账号被禁用 |
| 404 | `account_not_found` | false | 仅在已授权上下文返回 |
| 409 | `binding_conflict` | false | Idempotency-Key/引用冲突且请求不同、或 tombstone 引用 |
| 409 | `issuance_already_committed` | false | 创建结果已提交/提交中（哈希不可逆，fail-closed） |
| 409 | `refresh_already_committed` | false | 并发同刷新已完成（不撤销新一代） |
| 422 | `credential_invalid` | false | 凭据不匹配，**不可区分**是哪一项错 |
| 429 | `rate_limited` | true | 附 `Retry-After` |
| 503 | `provider_unavailable` | true | 未配置或提供方不可用 |

- 顺序契约：先认证客户端（401），再做凭据只读校验；**凭据错误一律 422**，仅在凭据有效但账号禁用时返回 **403** `account_disabled`。
- 错误不得泄漏 SQL、内部端点或提供方原始错误。

## 11. 速率限制与请求边界

- **顺序**：先按**来源**限流（socket 对端 / 连接来源），**在客户端认证之前**执行；**不得**信任任意 `X-Forwarded-For` / `Forwarded` 头作为来源。部署在反向代理后时，只允许配置显式声明的可信代理链。
- **客户端维度**：客户端认证后按 `client_id` 限流。
- **创建端点额外维度**：对 `credentials.identifier` 使用 **keyed digest**（purpose 分离 HMAC，key 来自门户 client_secret）限流，以约束针对同一标识的凭据猜测；**绝不**用原始 identifier，也**不用**对低熵标识的**非密钥**哈希（可被字典枚举）。
- **查询与刷新**同样受来源与客户端维度的限流约束；不存在绕过限流的公开路径。
- **触发时机**：`429 rate_limited` + `Retry-After` 必须在本端点**签发令牌或消费 refresh token 之前**返回；限流拒绝**不得**触碰提供方旧登录链（不写设备绑定、不写旧 Session、不赠送订阅）。
- **实现约束（提供方本地）**：使用**有界内存**的本地限流实现，**不引入新依赖**；达到容量按最旧淘汰，内存占用有上界。
- **数值默认值**由提供方实现设定，并在测试中固化（本规范不锁死具体数字）；测试必须覆盖：来源限流早于客户端认证、`client_id` 维度、identifier keyed 维度、`Retry-After` 存在、以及限流下旧链路零副作用。
- 任何公开的凭据处理端点都**必须**要求 Basic 客户端认证；不存在无 Basic 的公开凭据端点。

## 12. 失败语义与重试

- 网络错误或提供方 5xx：**不**标记账号失效；消费方保留既有快照并标记 `stale`/`unavailable`。
- 账号查询（`GET /account`）遇到网络中断同样**不**使令牌失效。
- 刷新歧义：按第 6 节用**同操作 ID + 同 refresh_token** 重试以发现结果；不用新操作 ID 盲重试，不恢复旧一代。
- 已消费且不可恢复的 refresh：只能**重新授权**。
- `429`/`503` 可按 `Retry-After`/退避重试。

## 13. 明确不承诺

- 不承诺 OAuth/OIDC/SCIM 兼容。
- 不承诺 provider-hosted 授权码流的安全属性；提交的凭据可读写整个账号，只有新授权是 `account:read`。
- 不承诺任意第三方业务字段的跨产品语义。
- 不承诺令牌可跨 issuer 或跨客户端使用。
