# Account Provider v1 实施计划

状态：**PLANNED**（本文档只描述计划与冻结契约；两仓库中尚未实现本协议的端点、迁移或客户端代码）

- 契约正本：本目录 `protocol.md` 与 `snapshot.schema.json`。
- **提供方（首个实现）**：CLtermux，见其仓库 `docs/account-provider-v1/README.md`（<https://github.com/chenming0v0/CLtermux-go/blob/master/docs/account-provider-v1/README.md>）。
- **消费方/客户端**：辰星通行证。用户在辰星门户输入提供方凭据，辰星把凭据送到提供方只读校验，由提供方签发令牌与快照。
- 关联 issue：功能需求 #706、默认作用域处理 #714（#714 针对**辰星 OAuth 新客户端的默认作用域**，与 Account Provider v1 的 `account:read` 无关，处理方式见第 13 节第 5 条）。
- 本特性跟踪 issue：辰星 [#715](https://github.com/chenming0v0/chenxing-auth/issues/715)、CLtermux [#4](https://github.com/chenming0v0/CLtermux-go/issues/4)。

## 0. 一句话目标

新增一个**通用、公开、产品中立**的「账号提供方 v1」协议：CLtermux 作为首个**提供方**实现协议端点；辰星通行证作为**消费方**，在**显式披露**后把用户在提供方的凭据瞬时送到提供方的**只读校验**流程，由提供方校验并签发**有作用域的不透明令牌**与快照。凭据本身并非只读，只有新签发的授权是 `account:read`。

## 1. 定位（必须先说清，避免被误读为标准合规）

本协议**不是** OAuth 2.0 / OIDC / SCIM，也**不是** password grant 的换皮：

- RFC 9700 §2.4 明确 **MUST NOT** 使用资源所有者密码凭据授权（ROPC）；本协议主动承认这条红线，不假装满足任何 OAuth/OIDC 合规。
  参考：<https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4>
- 本协议是**受信任消费方的凭据委托**：辰星门户在采集页向用户明确披露凭据会被中转校验；能读写账号的完整凭据都可能被提交，凭据 **MAY** 被消费方瞬时持有。
- 本协议**不宣称**与 provider-hosted Authorization Code + PKCE 具备等价安全性；后者是未来更强的替代路径。
- 对外一律称「Account Provider v1」，不复用 OAuth/OIDC 术语（无 authorize/token/introspect/JWKS 语义）。

## 2. Gate0 已通过的关键决策（不在本任务内重新讨论）

| 主题 | 冻结决策 |
| --- | --- |
| 协议形态 | 自研、版本化、公开文档；新授权只读 `account:read` |
| 提供方 | CLtermux 实现并托管协议端点；**不**新增托管登录 UI |
| 消费方 | 辰星通行证门户负责采集与 Basic 调用、Bearer 查询，并持有可逆加密令牌包 |
| 客户端 | 运营商注册的机密门户客户端；CL 提供 3 个环境变量配置的客户端 |
| 客户端密钥 | `ACCOUNT_PROVIDER_CLIENT_SECRET` ≥32 随机字节，**绝不复用**旧应用 HS256 secret |
| 认证 | 会话变更用 HTTP Basic；查询用 Bearer；`client_id` 全程显式绑定 |
| Issuer | **提供方（CL）**外部可达的 HTTPS 规范 origin；**不是**辰星 OIDC `APP_ISSUER`；不从 Host/反代头推导 |
| 凭据 | 仅瞬时中转、只读校验；**本协议不为请求中的凭据新增持久化副本或日志**；CL 既有卡密数据库仍是凭据权威存储，保持原样、不被本协议删除或改写 |
| 令牌存储 | 提供方只存 access/refresh 的 SHA256；辰星存**可逆加密令牌包**（AAD = providerUUID + bindingID + purpose）以便使用 |
| 绑定引用 | `client_binding_id` = 随机 UUID，永不复用 |
| 旧绑定 | 辰星 `linked_accounts` **不**保存用户卡密；新数据一律进新表 |
| 旧接口 | 旧 Login / 设备绑定 / 首登赠送 / 旧 Session 写入路径，以及旧移动 OIDC issuer，**零改动** |

## 3. 交付物

文档（本阶段，允许写入范围）：

- `docs/account-provider-v1/plan.md`（本文）
- `docs/account-provider-v1/protocol.md`（冻结线上契约，提供方视角）
- `docs/account-provider-v1/compatibility.md`（辰星消费方侧的兼容与迁移策略）
- `docs/account-provider-v1/snapshot.schema.json`（快照 JSON Schema）
- `docs/account-provider-v1/fixtures/*`（**通用**假数据夹具，Rust/Go 测试复用）
- CLtermux 仓库 `docs/account-provider-v1/README.md` 与镜像 `fixtures/*`（与辰星**逐字节一致**）

实现（后续阶段，本阶段**不写**任何业务源码、迁移或 `openapi.yaml` 实现路径）：

- 阶段 A（提供方，CL）：新完整端点 + 新迁移 + 聚焦兼容测试 + 真实 Go/MySQL CI。
- 阶段 B（消费方，辰星）：新独立表/模块 + 经认证的管理/门户消费方 API + 前端接入 + OpenAPI/文档。

## 4. 共享夹具（跨仓库同源）

| 文件 | 用途 |
| --- | --- |
| `metadata.json` | 公开元数据发现响应（通用标签：账户/密码） |
| `account-snapshot.json` | 快照根，`GET account` 200 响应体；也等于创建响应的内嵌快照 |
| `link-session-request.json` | 创建绑定请求体 |
| `link-session-response.json` | 创建绑定 201 响应（令牌包 + 快照） |
| `refresh-request.json` | 刷新请求体 |
| `refresh-response.json` | 刷新 200 响应（轮换后的令牌包 + 快照） |
| `revoke-request.json` | 撤销请求体 |
| `error-envelope.json` | 错误信封样例 |
| `snapshot-unknown.json` | 含未知顶层字段与未知字段类型的**有效**快照夹具（`subscription.kind = "unknown"` 是**已知**取值） |
| `invalid-subscriptions.json` | subscription 替换用例清单（无效/边界输入），**不是端点负载**，禁止作为 schema 根校验；测试用其替换 `account-snapshot.json` 的 `subscription` 后按 `expect` 断言 reject/accept |

- 夹具一律**产品中立**：`uid` 用 `acct-1001`、`account` 用 `demo-account-1001`、`issuer`/`homepage` 用 `provider.example.com`；**不**出现 `cltermux:` 前缀。只有 CL 仓库 README 解释旧 UID 映射。
- `invalid-subscriptions.json` 只列出替换补丁（case 名 + `subscription` + 期望结果），不需要复制完整快照根。
- 所有令牌、UUID、账号均为**假值**，不含任何真实凭据。
- 共享夹具在两仓库必须完全一致，任一修改需同源复制。

## 5. 阶段、依赖与顺序

依赖链：**文档 → 提供方（CL）实现 → 消费方（辰星）实现**。辰星消费方的 DTO、新表与 OpenAPI 都要冻结在 `protocol.md` 之后；提供方先用真实 Go/MySQL CI 证明旧接口未破坏。

### 阶段 A：提供方（CL）协议实现 + 迁移 + 兼容测试（在文档冻结之后）

1. 新增独立 provider 服务端模块（Basic 认证、只读凭据校验、令牌签发、哈希存储、刷新轮换、绑定 tombstone）。
2. 新增独立迁移，**不**修改旧表语义、**不**自动迁移旧绑定。
3. 新 mapper 只读复用既有 `IntegrationService.Verify` / `IntegrationRepo.GetByCredentials` 投影，**绝不**调用 `AuthService.Login`。
4. 补真实 Go/MySQL CI（当前工作流只 build，不跑回归）。
5. 新路径必须一次性包含 revoke 与刷新 CAS，不允许以「能力不完整」形态提交。
6. 速率限制：来源限流**早于客户端认证**（**不**信任任意 `X-Forwarded-For`/`Forwarded`），认证后按 `client_id` 限流，创建端点额外按 `credentials.identifier` 的 **keyed digest**（非原始值、非低熵明文哈希）限流；CL 用**有界内存**本地实现且**不引入新依赖**；`429 + Retry-After` 在签发/消费前返回且不触碰旧登录链。

### 阶段 B：消费方（辰星）客户端接入 + 消费方 API + 前端

1. **辰星作为客户端调用阶段 A 的提供方端点**：管理员保存与提供方 issuer origin 一致的 `base_url`、`client_id`、`client_secret`；门户采集后经 Basic 创建/刷新，经 Bearer 查询。
2. 新独立表/模块：provider 配置、bindings、token operations、revocation outbox。
3. 新增**独立的、经认证的**管理端点与门户聚合/操作端点（消费方 API）；provider 的 `/.well-known` 与 4 个协议端点**不是**辰星实现的。
4. 细节在阶段 B 冻结进 `openapi.yaml`；外部 HTTP 契约变化后调用 `sync-openapi`。
5. 前端 `web/src` 门户接入（designer 负责），复用 `@chenxing/ui` 正式组件；临时回退需登记 issue。

### 阶段 C：原子提交、CI 监控与发布

1. 父编排把各角色改动按仓库/阶段做成原子提交。
2. 按 SHA 持续监控 CI，直到通过或外部阻塞；只报告「已触发」不算完成。
3. 辰星：`dev` 上先把 `Cargo.toml` 与 `Cargo.lock` 的版本改成不带 `v` 的字面量 `1.1.35`（发布前复查 Release 列表，当前最新 `v1.1.34`），再 `dev → releases`；tag 与 Release 名称为 `v1.1.35`。本地附注标签个人凭据推送，验证 tag 触发的 Build And Publish 产出真实 Release 与 6 个归档 + `SHA256SUMS`，下载校验后才算完成。
4. CL：保留 master 上两个先于本任务的本地提交（父编排已复核：`oldsql/` 自动导入只在用户 SQL 文件存在时改安装/升级路径，删除的是 `cmd/migrate-data` 工具而非 `cmd/migrate`），两者原样保留，推送前再复核；不猜版本号。
5. 一键安装两行命令保持不变。

## 6. 评审门

- **Gate1（阶段 A 后，独立 Oracle）**：提供方旧 `login`/会话/设备/订阅/token 路径不变量；新旧令牌隔离；新路径不触发 `AuthService.Login`；凭据不泄漏。
- **Gate2（阶段 B 后，独立安全/兼容/互操作评审）**：辰星旧 adapter 配置/绑定 JSON 与移动 exchange/scope 全部存活；刷新轮换并发与丢响应；加密 AAD；SSRF/恶意字段；UI 可信渲染。
- 评审由父编排指派，实现者不自评。

## 7. 测试与验证所有权

- 实现代理只做允许的轻量静态检查（Rust 侧仅 `cargo fmt --check`；**禁止**任何产生 `target/` 的命令、禁止调用 `test_sh/test.sh`）。
- 用例由实现者编写、父编排执行完整 CI 验证。
- 阶段 A 关键用例：提供方旧 `/login` 与会话、设备绑定、旧 verify/lookup、旧 token 路径的 golden 契约；新路径不得绑定设备、不得轮换旧 App Session、不得赠送订阅、不得泄漏凭据；keyed 指纹不得可逆出凭据；刷新并发/丢响应；速率限制（来源限流早于客户端认证且不信任转发头、`client_id` 维度、identifier keyed 维度、`Retry-After` 在签发/消费前、限流下旧链零副作用）。
- 阶段 B 关键用例：辰星旧 adapter/配置/绑定 JSON、移动 exchange 与旧 scope；消费方令牌包加密与 AAD；刷新并发、barrier、丢响应；SSRF 防护；恶意 fields；到期状态机。
- 若工具链或外部服务不可用导致无法验证，必须在变更说明写明原因，不得声称通过。

## 8. 兼容与回滚

- 旧二进制回滚后可忽略新表；旧 settings/bindings 照样解码。
- 回滚保留增量迁移，**不**删库、**不**丢数据。
- 新提供方为 opt-in：CL 新端点可达后才启用；本任务不做任何生产部署。
- 详细策略见 `compatibility.md`。

## 9. 明确不做（本阶段）

- 不实现任何端点、迁移、OpenAPI 路径或前后端源码。
- 不引入新依赖或新架构决策；已有决议以 Gate0 与第 13 节为准。
- 不提供 OAuth/OIDC/SCIM 兼容承诺。
- 不实现自动远程媒体加载、动态 HTML/表单、服务端模板。
- 不删除或改写旧接口、旧字段、旧移动端交换流程；不改变旧移动 OIDC issuer。

## 10. 角色与写入范围

| 角色 | 写入范围 | 说明 |
| --- | --- | --- |
| 文档（本任务） | 两仓库 `docs/account-provider-v1/**` | 只写文档与夹具；不碰源码、迁移、OpenAPI 实现路径 |
| CL fixer（提供方） | CL 新 provider 端点/迁移/测试 | 相位 A；一次性提交完整能力（含 revoke、刷新 CAS） |
| 辰星后端 fixer（消费方） | 辰星新表/模块/消费方 API/OpenAPI | 相位 B；不重写旧 adapter；旧 app 零改动 |
| designer | 辰星 `web/src` 门户接入 UI | 独占前端写范围，复用 `@chenxing/ui` 正式组件 |
| 父编排 | git/CI/版本/发布 | 唯一执行提交、推送、打标签、监控 CI |

- 任何实现代理**禁止**执行产生 `target/` 的命令或 `test_sh/test.sh`；只允许 `cargo fmt --check` 等不编译检查。
- 变更后必须跑 `src-line-limit`；当前处于 500 行上限的文件包括 `src/integrations/cltermux/validation.rs`（旧 adapter）、`src/users/domain.rs`、`src/audit.rs`。任何被改动的文件一旦 >500 行必须拆分，不允许 >500 的改动文件。

## 11. 风险登记

| 风险 | 缓解 |
| --- | --- |
| 新路径误触发提供方旧登录副作用 | 只读复用投影；Gate1 用 golden 测试证明设备/会话/订阅/mobile 未被触碰 |
| 凭据进入日志或持久层 | 代码评审 + 测试断言；原始凭据不落库、不写日志；只存 keyed 指纹 |
| 提供方存储非密钥凭据哈希被离线爆破 | 指纹必须为 purpose 分离的 HMAC，绝不存 unkeyed digest |
| 刷新并发双发 | 原子消费 + CAS + operation marker；歧义重试用同操作 ID |
| tombstone 被延迟请求复活 | binding generation + tombstone 校验在条件提交内 |
| 旧回滚丢数据 | 增量迁移保留；新表独立；旧二进制忽略新表 |
| Idempotency-Key 指纹冲突 | 409 fail-closed，不做重放 |
| 旧 legacy scope 被隐式塞进新客户端 OAuth 默认 | 新客户端 OAuth 默认仅 `openid`/`profile`/`email`；Account Provider 默认仅 `account:read`；既有 grants 与显式配置 scope 保留；见第 13 节第 5 条 |
| 生产密钥混用 | 独立 `ACCOUNT_PROVIDER_CLIENT_SECRET` ≥32 字节，绝不复用 HS256 secret |

## 12. 提交与 CI 检查清单

- 每个原子提交按 SHA 监控对应 CI 运行，直到通过或记录外部阻塞；只报「已触发」不算完成。
- 辰星：发布前复查 Release 列表（当前最新 `v1.1.34` → 计划 `v1.1.35`）；在 `dev` 上把 `Cargo.toml` 与 `Cargo.lock` 的版本写成不带 `v` 的字面量 `1.1.35`，`dev → releases`，本地附注标签 + 个人凭据推送，tag 与 Release 名为 `v1.1.35`；确认 tag 触发 Build And Publish 并产出真实 Release、非空归档（6 个架构归档 + `SHA256SUMS`），**下载并校验校验和**后才停止。当前 `release-tag.yml` 不存在，不臆造工作流。
- CL：补真实 Go/MySQL 回归 CI；保留 master 上两个先行提交（复核后推送）；不猜版本号；一键安装两行命令不变。
- 两仓库增量部署、提供方 opt-in；本任务不做生产部署。

## 13. 已解决决策（父编排已裁定）

1. **元数据标签**：由**提供方实现**定义，**不**新增 CL 环境变量。通用规范支持任意安全标签（单值 ≤128 UTF-8 字节）；输入恰好 2 个（`identifier`/`secret`），元数据恰好 3 个描述键（`identifier_label`/`secret_label`/`identifier_sensitive`）。CL 用「卡密账号」「卡密密码」，`identifier_sensitive: true`。
2. **刷新响应形状**：与创建**同形状**（令牌包 + `snapshot`）。`refresh-response.json` 即此形状。
3. **`issuance_already_committed` 语义**：fail-closed 返回 409；「只存哈希、无法重放 raw token」的约束位于**提供方**。
4. **`account` 字段**：非空、非敏感展示账号（`minLength: 1`），≤128。
5. **作用域边界（两套默认互不相同）**：Account Provider v1 只有 `account:read`，它**不是**辰星 OAuth 的 scope 体系。#714 处理的是**辰星 OAuth 新客户端的默认作用域**（`openid`/`profile`/`email`），**不是** Account Provider 的默认：只把 `cltermux:access` 从**新客户端**的通用默认中移除，避免新客户端被隐式授予 legacy scope。既有所有客户端与 grants、显式配置的 legacy scope、以及 exchange 300s 线上取值**全部保留不变**；**不**删除任何已存在的 grants 或已配置 scope。
6. **凭据存储边界**：**本协议不为请求中的原始凭据新增任何持久化副本或日志**；CL 既有卡密数据库仍是凭据权威存储，**保持原样**，本协议不要求也不允许删除既有 key/卡密字段。短暂的原始凭据中转暴露被显式承认。

无遗留待确认项；如需变更以上裁定，回到本文件显式修改。
