# Account Provider v1 实施计划

状态：**Implemented**

本文档是契约与边界正本，不是「尚未开工」的计划书。辰星消费方已经落地：`src/resource_services/**`、迁移 `0058_account_portal.sql` / `0059_resource_services.sql`、经认证的管理/门户 API、OpenAPI、门户与管理 UI、`POST /api/v1/auth/chenxing/exchange`。提供方协议端点仍由 CLtermux 托管，见其仓库 `docs/account-provider-v1/README.md`（<https://github.com/chenming0v0/CLtermux-go/blob/master/docs/account-provider-v1/README.md>）。剩余实现缺口见第 14 节，不得把正本改回 PLANNED，也不得假装本仓库没有代码。

- 契约正本：本目录 `protocol.md` 与 `snapshot.schema.json`。
- **提供方（首个实现）**：CLtermux。
- **消费方/客户端**：辰星通行证。用户在辰星门户输入提供方凭据，辰星把凭据送到提供方只读校验，由提供方签发令牌与快照。
- 关联 issue：功能需求 #706、默认作用域处理 #714（#714 针对**辰星 OAuth 新客户端的默认作用域**，与 Account Provider v1 的 `account:read` 无关，处理方式见第 13 节第 5 条）。
- 本特性跟踪 issue：辰星 [#715](https://github.com/chenming0v0/chenxing-auth/issues/715)、CLtermux [#4](https://github.com/chenming0v0/CLtermux-go/issues/4)。文档与 `linked_accounts` 淘汰：[#720](https://github.com/chenming0v0/chenxing-auth/issues/720)。

## 0. 一句话目标

新增一个**通用、公开、产品中立**的「账号提供方 v1」协议：CLtermux 作为首个**提供方**实现协议端点；辰星通行证作为**消费方**，在**显式披露**后把用户在提供方的凭据瞬时送到提供方的**只读校验**流程，由提供方校验并签发**有作用域的不透明令牌**与快照。凭据本身并非只读，只有新签发的授权是 `account:read`。

## 1. 定位（必须先说清，避免被误读为标准合规）

本协议**不是** OAuth 2.0 / OIDC / SCIM，也**不是** password grant 的换皮：

- RFC 9700 §2.4 明确 **MUST NOT** 使用资源所有者密码凭据授权（ROPC）；本协议主动承认这条红线，不假装满足任何 OAuth/OIDC 合规。
  参考：<https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4>
- 本协议是**受信任消费方的凭据委托**：辰星门户在采集页向用户明确披露凭据会被中转校验；能读写账号的完整凭据都可能被提交，凭据 **MAY** 被消费方瞬时持有。
- 本协议**不宣称**与 provider-hosted Authorization Code + PKCE 具备等价安全性；后者是未来更强的替代路径。
- 对外一律称「Account Provider v1」，不复用 OAuth/OIDC 术语（无 authorize/token/introspect/JWKS 语义）。

Gate0 此项不重开。

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
| 旧绑定 | Gate0：辰星旧 `linked_accounts` **不**保存用户卡密；新数据一律进新表。后续 0059 **有意**淘汰该定制层（`DROP TABLE linked_accounts`），见 `compatibility.md` |
| 旧接口 | 提供方旧 Login / 设备绑定 / 首登赠送 / 旧 Session 写入路径，以及辰星旧移动 OIDC issuer，**零改动** |

## 3. 交付物（已落地 vs 文档）

文档（正本仍在本目录）：

- `docs/account-provider-v1/plan.md`（本文）
- `docs/account-provider-v1/protocol.md`（冻结线上契约，提供方视角）
- `docs/account-provider-v1/compatibility.md`（辰星消费方侧的兼容与迁移策略）
- `docs/account-provider-v1/snapshot.schema.json`（快照 JSON Schema）
- `docs/account-provider-v1/fixtures/*`（**通用**假数据夹具，Rust/Go 测试复用）
- CLtermux 仓库 `docs/account-provider-v1/README.md` 与镜像 `fixtures/*`（与辰星**逐字节一致**）

辰星消费方（本仓库已落地，不是后续阶段）：

- 模块 `src/resource_services/`（产品中立；不实现提供方端点）
- 表 `resource_service_providers` / `resource_service_bindings` / `resource_service_operations` / `resource_service_revocation_outbox`（0058 以 `account_portal_*` 创建，0059 改名并声明资源服务 scope）
- 管理 API `/api/v1/admin/resource-services*`、门户 `/api/v1/auth/resource-services*`、`GET /api/v1/auth/oauth-scopes`、兑换 `POST /api/v1/auth/chenxing/exchange`
- 前端控制台「资源服务」与管理面板；`openapi.yaml` 已收录消费方路径
- 0059 **有意** `DROP TABLE linked_accounts`，并 `DELETE FROM app_settings WHERE setting_key = 'account_providers'`。运行时已无 `src/linked_accounts` 模块；`src/db/mod.rs` 仍 include 历史迁移 `0053_cltermux_linked_accounts.sql`，这是迁移链需要，不是活表。

提供方（CLtermux，不在本仓库实现）：

- `GET /.well-known/account-provider` 与 4 个协议端点。

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

## 5. 阶段状态

依赖链当时是**文档 → 提供方（CL）实现 → 消费方（辰星）实现**。文档与辰星消费方已合入；提供方端点仍在 CLtermux。

### 阶段 A：提供方（CL）

提供方托管协议端点、独立迁移、只读复用既有校验投影、**绝不**调用 `AuthService.Login`。完整能力含 revoke 与刷新 CAS。速率限制：来源限流早于客户端认证（不信任任意 `X-Forwarded-For`/`Forwarded`），认证后按 `client_id`，创建端点额外按 `credentials.identifier` 的 keyed digest。细节见 `protocol.md`。

### 阶段 B：消费方（辰星）— 已落地

1. 管理员保存与提供方 issuer origin 一致的 `base_url`（当前实现为 `issuer` 列）、`client_id`、`client_secret`；门户采集后经 Basic 创建/刷新，经 Bearer 查询。
2. 独立表/模块：provider 配置、bindings、token operations、revocation outbox（现名 `resource_service_*`）。
3. 独立、经认证的管理端点与门户聚合/操作端点；provider 的 `/.well-known` 与 4 个协议端点**不是**辰星实现的。
4. 外部 HTTP 契约已进 `openapi.yaml`。
5. 前端 `web/src` 门户与管理接入。

### 阶段 C：发布

版本号、`dev → releases`、tag 与 Release 由发布流程处理，不在 #720 范围。一键安装两行命令保持不变。

## 6. 评审门

- **Gate1（提供方）**：旧 `login`/会话/设备/订阅/token 路径不变量；新旧令牌隔离；新路径不触发 `AuthService.Login`；凭据不泄漏。
- **Gate2（消费方）**：刷新轮换并发与丢响应；加密 AAD；SSRF/恶意字段；UI 可信渲染。旧 `linked_accounts` 形状兼容**不再**作为 Gate2 项——该表已按 0059 淘汰。
- 第 14 节缺口关闭前，不得声称 Gate2 全绿。

## 7. 测试与验证所有权

- 实现代理只做允许的轻量静态检查（Rust 侧仅 `cargo fmt --check`；**禁止**任何产生 `target/` 的命令、禁止调用 `test_sh/test.sh`）。
- 用例由实现者编写、父编排执行完整 CI 验证。
- 阶段 A 关键用例：提供方旧 `/login` 与会话、设备绑定、旧 verify/lookup、旧 token 路径的 golden 契约；新路径不得绑定设备、不得轮换旧 App Session、不得赠送订阅、不得泄漏凭据；keyed 指纹不得可逆出凭据；刷新并发/丢响应；速率限制。
- 阶段 B 关键用例：消费方令牌包加密与 AAD；刷新并发、barrier、丢响应；SSRF 防护；恶意 fields；到期状态机；兑换走资源服务绑定与 `{slug}:access` 交集，而不是已删除的 `linked_accounts`。
- 若工具链或外部服务不可用导致无法验证，必须在变更说明写明原因，不得声称通过。

## 8. 兼容与回滚

- 0059 `DROP TABLE linked_accounts` 是**有意淘汰**旧 CLtermux 定制层，不是事故。旧二进制回滚**不能**靠「忽略新表」恢复旧绑定。
- 回滚保留增量迁移，**不**删库；新 `resource_service_*` 表仍在，旧二进制不认识它们。
- 新提供方为 opt-in：CL 新端点可达且管理员配置资源服务后才启用。
- 详细策略见 `compatibility.md`。

## 9. 明确不做（Gate0 冻结，不重开）

- 不把本协议说成 OAuth 2.0 / OIDC password grant 或任何 ROPC 换皮。
- 不提供 OAuth/OIDC/SCIM 兼容承诺。
- 不实现自动远程媒体加载、动态 HTML/表单、服务端模板。
- 不改提供方旧 Login / 设备绑定 / 首登赠送 / 旧 Session 写入路径，不改变辰星旧移动 OIDC issuer（`APP_ISSUER`）。
- 不把 AP 协议令牌的 `account:read` 与辰星 OAuth 的 `{slug}:access` 焊成同一套 scope。

## 10. 角色与写入范围（历史编排；#720 只改正本）

| 角色 | 写入范围 | 说明 |
| --- | --- | --- |
| 文档 | 两仓库 `docs/account-provider-v1/**` | 正本与夹具 |
| CL fixer（提供方） | CL 新 provider 端点/迁移/测试 | 相位 A |
| 辰星后端 fixer（消费方） | `src/resource_services/**`、迁移、消费方 API、OpenAPI | 相位 B；已合入 |
| designer | 辰星 `web/src` 门户接入 UI | 已合入 |
| 父编排 | git/CI/版本/发布 | 唯一执行推送、打标签、监控 CI |

剩余缺陷（#716–#719）另立 issue，不重开 Gate0。

## 11. 风险登记

| 风险 | 缓解 |
| --- | --- |
| 新路径误触发提供方旧登录副作用 | 只读复用投影；Gate1 用 golden 测试证明设备/会话/订阅/mobile 未被触碰 |
| 凭据进入日志或持久层 | 代码评审 + 测试断言；原始凭据不落库、不写日志；只存 keyed 指纹 |
| 提供方存储非密钥凭据哈希被离线爆破 | 指纹必须为 purpose 分离的 HMAC，绝不存 unkeyed digest |
| 刷新并发双发 | 原子消费 + CAS + operation marker；歧义重试用同操作 ID |
| tombstone 被延迟请求复活 | binding generation + tombstone 校验在条件提交内 |
| 旧二进制回滚丢绑定 | 0059 已 DROP `linked_accounts`：回滚旧二进制**不能**恢复旧定制层绑定；运维只能从 0059 之前的备份恢复，或让用户在资源服务上重新绑定。见 `compatibility.md` |
| Idempotency-Key 指纹冲突 | 409 fail-closed，不做重放 |
| 旧 legacy scope 被隐式塞进新客户端 OAuth 默认 | 新客户端 OAuth 默认仅 `openid`/`profile`/`email`；Account Provider 默认仅 `account:read`；资源服务 `{slug}:access` 是第三类、正交的辰星 OAuth scope，见第 13 节第 5 条 |
| 生产密钥混用 | 独立 `ACCOUNT_PROVIDER_CLIENT_SECRET` ≥32 字节，绝不复用 HS256 secret |
| 匿名 Discovery 泄露 restricted 资源 scope | 目标态：匿名 `scopes_supported` 只宣布 public；restricted 只出现在带 `client_id` 的目录。实现见 #716 |

## 12. 提交与 CI 检查清单

- 每个原子提交按 SHA 监控对应 CI 运行，直到通过或记录外部阻塞；只报「已触发」不算完成。
- 两仓库增量部署、提供方 opt-in。
- 一键安装两行命令不变。

## 13. 已解决决策（父编排已裁定）

1. **元数据标签**：由**提供方实现**定义，**不**新增 CL 环境变量。通用规范支持任意安全标签（单值 ≤128 UTF-8 字节）；输入恰好 2 个（`identifier`/`secret`），元数据恰好 3 个描述键（`identifier_label`/`secret_label`/`identifier_sensitive`）。CL 用「卡密账号」「卡密密码」，`identifier_sensitive: true`。
2. **刷新响应形状**：与创建**同形状**（令牌包 + `snapshot`）。`refresh-response.json` 即此形状。
3. **`issuance_already_committed` 语义**：fail-closed 返回 409；「只存哈希、无法重放 raw token」的约束位于**提供方**。
4. **`account` 字段**：非空、非敏感展示账号（`minLength: 1`），≤128。
5. **作用域边界（三类，彼此正交、互不混用）**：
   - **Account Provider v1 协议令牌**只有 `account:read`。它**不是**辰星 OAuth 的 scope 体系，也不出现在辰星 OIDC Discovery 的 `scopes_supported` 里。令牌包校验仍要求 AP 侧 `scope = account:read`。
   - **辰星 OAuth 基础 scope**：#714 处理的是**新客户端的默认作用域**（`openid`/`profile`/`email`）。只把 `cltermux:access` 从**新客户端**的通用默认中移除，避免新客户端被隐式授予 legacy scope。既有客户端与 grants、显式配置的 scope **不**被本条删除。
   - **第三类：资源服务声明的 `{slug}:access`**（缺省 `format!("{slug}:access")`，管理员可改，但不得占用 OIDC 保留名）。这是辰星 OAuth 侧资源服务的授权 scope，与 AP `account:read` **正交**：前者走授权码/grant/exchange，后者只出现在提供方签发的 AP 令牌包。`POST /api/v1/auth/chenxing/exchange` 用 OAuth AT 与已启用资源服务 scope 的交集选服务，再查该服务上的绑定；**不**再用已删除的 `linked_accounts`。匿名 Discovery（`/.well-known/openid-configuration` 的 `scopes_supported`）**只宣布 public** 资源服务 scope；`restricted` 只出现在带 `client_id` 的目录（`GET /api/v1/auth/oauth-scopes?client_id=`）与该应用 allowlist。此 Discovery 目标态由 [#716](https://github.com/chenming0v0/chenxing-auth/issues/716) 修代码，正本先对齐目标态。
6. **凭据存储边界**：**本协议不为请求中的原始凭据新增任何持久化副本或日志**；CL 既有卡密数据库仍是凭据权威存储，**保持原样**，本协议不要求也不允许删除既有 key/卡密字段。短暂的原始凭据中转暴露被显式承认。

无遗留待确认项；如需变更以上裁定，回到本文件显式修改。不重开 Gate0。

## 14. 已关闭的实现缺口

正本状态是 Implemented。下列缺口已在消费方落地，跟踪 issue 已关闭：

| Issue | 已落地 |
| --- | --- |
| [#716](https://github.com/chenming0v0/chenxing-auth/issues/716) | 匿名 Discovery 只宣布 public 资源服务 scope |
| [#717](https://github.com/chenming0v0/chenxing-auth/issues/717) | keyed HMAC；创建用真实 `binding_id`；刷新指纹绑 binding 身份，不绑会旋转的 refresh token |
| [#718](https://github.com/chenming0v0/chenxing-auth/issues/718) | 提供方 `already_committed` 先探本地，不 `fail_operation` |
| [#719](https://github.com/chenming0v0/chenxing-auth/issues/719) | 同步在提供方 200 时落库 `snapshot_json`；CAS 未命中返回当前 live 行，不 409 |

无新的正本级剩余缺口。后续缺陷另开 issue，跟踪在父 issue [#715](https://github.com/chenming0v0/chenxing-auth/issues/715)。
