# Account Provider v1 — 辰星侧兼容与迁移策略

状态：**Implemented**。本文件描述辰星**消费方**侧的兼容与迁移策略，与已落地的 `src/resource_services/**`、0058/0059 对齐。提供方端点仍由 CLtermux 托管，不在本仓库实现。

## 1. 方向与核心原则

- **提供方**（CLtermux）实现并托管协议端点；**辰星是消费方/客户端**。
- 辰星在新协议中的角色：门户采集提供方凭据 → Basic 调用提供方创建/刷新 → Bearer 调用提供方查询 → 持有可逆加密令牌包以便使用。
- **提供方端点与消费方 API 必须分清**：`/.well-known/account-provider` 与 4 个协议端点由提供方托管；辰星只提供**独立的、经认证的**管理/门户消费方 API。
- **新数据进新表**：通用 provider 数据只写入 `resource_service_*` 表。
- **旧 CLtermux 定制层已淘汰（有意，不是事故）**：`migrations/0059_resource_services.sql` 执行 `DROP TABLE IF EXISTS linked_accounts`，并 `DELETE FROM app_settings WHERE setting_key = 'account_providers'`。旧表不保存用户卡密，因此没有可迁移的凭据；0059 **不**做旧绑定自动迁移，而是直接丢掉定制层行。运行时已无 `src/linked_accounts` 模块。
- **回滚不能靠「忽略新表」恢复旧绑定**：DROP 之后，旧二进制即使忽略 `resource_service_*` 也读不到 `linked_accounts`。见第 13 节。

## 2. 数据库（辰星侧）

当前表（0058 以 `account_portal_*` 创建，0059 改名为 `resource_service_*`）：

- `resource_service_providers`（`issuer` 与提供方 origin 一致、`client_id`、`client_secret` 密文、`revision`、slug、以及资源服务向辰星 OAuth 声明的 `scope` / `scope_access` / `allowed_client_ids`）
- `resource_service_bindings`（绑定 UUID、provider、uid、issuer、grant generation、tombstone、加密令牌包、快照）
- `resource_service_operations`（`Idempotency-Key` 指纹、状态、lease）
- `resource_service_revocation_outbox`（不可变撤销任务）

约束：

- 通用 provider 数据**不**写入已删除的 `linked_accounts`。
- 迁移链保留历史文件：`0053_cltermux_linked_accounts.sql` 仍被 `src/db/mod.rs` include，空库会先建再被 0059 DROP。这是迁移链完整性，不是运行时表。
- 回滚时**保留**增量迁移，**不**删库，也**不**重建 `linked_accounts`。
- 不提供任何自动迁移旧 `linked_accounts` 行的路径。

## 3. 模块与代码边界

- 新消费方源代码**产品中立**：运行时模块是 `src/resource_services/`，不出现产品名硬编码。
- 旧 `src/integrations/cltermux/` 与 `src/linked_accounts/` 已随定制层淘汰删除，**不**再作为兼容层保留。
- 旧线上字段名不复用到 AP 协议路径；AP 快照语义只在新协议里表达。
- 资源服务向辰星 OAuth 声明的 `{slug}:access` 是第三类 scope（见第 8 节），写在 `resource_service_providers.scope`，**不是** AP 令牌包里的 `account:read`。

## 4. 管理面与 API（消费方侧）

已落地路径（`openapi.yaml` 已收录）：

- 管理：`/api/v1/admin/resource-services` 及 `/{id}`、`/{id}/enable`、`/{id}/disable`
- 门户：`/api/v1/auth/resource-services`、`/bindings`、刷新、同步、解绑
- 权限目录：`GET /api/v1/auth/oauth-scopes?client_id=`
- 兑换：`POST /api/v1/auth/chenxing/exchange`

行为：

- 旧非资源服务 API 契约不受本协议替换；只有外部 HTTP 契约变化时才调用 `sync-openapi`。
- 消费方在未配置 / 未启用资源服务时，相关绑定与兑换返回 `503 provider_unavailable`，不干扰登录与 OIDC。
- 提供方自身的端点是提供方行为，不由辰星实现。
- 创建资源服务前会向提供方 `/.well-known/account-provider` 拉取凭据标签；`client_secret` 只在创建时提交，后续列表和查询不返回明文或哈希。

## 5. 前端

- 门户：`web/src` 控制台「资源服务」页；管理：OAuth 设置下的资源服务面板。复用 `@chenxing/ui` 正式组件。
- 通用连接**只**用于资料读取；披露文案必须说明凭据会瞬时经过辰星。
- 通用连接**不是**移动登录授权，也不隐藏其它账号入口。

## 6. 旧连接与移动端

- 辰星旧移动 OIDC issuer（`APP_ISSUER`）完全不变。
- **绝不**声称通用连接自动授权移动端。
- `POST /api/v1/auth/chenxing/exchange` 仍签发 ≤300s RS256 会话令牌；响应不含 `access_token` / `refresh_token` / `id_token`。
- 兑换**不再**走 `linked_accounts.resolve` 或硬编码 `cltermux:access`。实现用 OAuth AT 与已启用资源服务声明 scope 的交集选择服务，再读取该服务上的 live 绑定。这是定制层淘汰后的目标契约，与 AP `account:read` 正交。
- 旧 `cltermux:access` 作为新客户端隐式默认的行为已按 #714 移除；新客户端 OAuth 默认仍是 `openid` / `profile` / `email`。

## 7. 一致性与并发

- **解绑（unlink）**：本地 tombstone + 持久化撤销任务**原子**提交；远端重试，最终一致。
- **创建/刷新**：
  1. 短事务领取操作 + lease，**HTTP 调用提供方期间不持有 DB 锁**。
  2. 短条件提交校验：当前 session/CSRF/owner、provider 身份与 revision、uid/issuer、grant/binding generation。
  3. 在途陈旧响应不能复活已 tombstone 的绑定。
- **歧义刷新重试**：网络错误/5xx 时用**同操作 ID + 同 refresh_token** 重试以发现结果；不用新操作 ID 盲重试，不恢复旧一代。
- **本地新一代优先**：若消费方已持久化新一代令牌包，则它以本地为准覆盖重复响应；若提供方已提交而令牌包丢失，只能显式重新授权并清理。
- **账号查询网络中断不使令牌失效**；成功同步落库 `snapshot_json`。并发 CAS 未命中（generation/revision 已前进）返回当前 live 行，不 409、不改令牌包（#719）。
- provider 身份（端点/客户端）在有未完成 grants/operations/outbox 时**不可编辑**。

## 8. 作用域（三类，彼此正交）

1. **Account Provider v1 协议令牌**：只有 `account:read`。它**不是**辰星 OAuth 的 scope，也不提供 `cltermux:access`。提供方签发的令牌包 `scope` 必须是 `account:read`。
2. **辰星 OAuth 基础 scope**：#714 只针对**新客户端的默认作用域**（`openid`/`profile`/`email`）。既有客户端、既有 grants、显式配置的 scope **不**被本条删除。
3. **资源服务声明的 `{slug}:access`**：辰星 OAuth 的第三类 scope。缺省 `format!("{slug}:access")`，由 `resource_service_providers` 声明，`scope_access` 为 `public` 或 `restricted`。它授权「该 OAuth 客户端能否代表用户调用兑换等资源服务能力」，与 AP `account:read` 正交，不得写进 AP 令牌包，也不得当成 AP 协议能力。

匿名 Discovery（`GET /.well-known/openid-configuration` 的 `scopes_supported`）**只宣布 public** 资源服务 scope + 基础 scope；`restricted` 只出现在带 `client_id` 的目录（`GET /api/v1/auth/oauth-scopes?client_id=`）以及该应用的 allowlist。此条是正本目标态；实现由 [#716](https://github.com/chenming0v0/chenxing-auth/issues/716) 修。

## 9. 新旧产物对照（含方向）

| 产物 | 旧 CLtermux 定制层（0059 已淘汰） | 新（资源服务 / AP v1 消费方） |
| --- | --- | --- |
| 数据表（辰星） | `linked_accounts` + `app_settings.account_providers`（0059 DROP / DELETE） | `resource_service_providers` / `bindings` / `operations` / `revocation_outbox` |
| 运行时模块 | `src/linked_accounts`、旧 adapter（已删） | `src/resource_services/` |
| 配置键（辰星） | 旧应用设置 | 管理面 `issuer`/`client_id`/`client_secret` + slug/scope 声明；提供方侧仍是 `ACCOUNT_PROVIDER_*` 三键 |
| 客户端密钥 | 旧应用 HS256 secret | 独立 ≥32 随机字节机密客户端，绝不复用 |
| 令牌存储 | 旧 App / mobile token | **提供方**只存 SHA256；**辰星**存可逆加密包（AAD = providerUUID + bindingID + purpose） |
| 提供方端点 | 旧 auth/agent API（CL 侧仍保留、零改动） | 提供方托管 `/.well-known/account-provider` + 4 个协议端点（**非辰星实现**） |
| 消费方 API | 旧 resolve 绑定查询 | `/api/v1/admin/resource-services*`、`/api/v1/auth/resource-services*` |
| 错误 | 旧错误结构 | 消费方 API 沿用辰星错误信封；提供方协议错误见 `protocol.md` |
| 移动兑换 | 旧 `linked_accounts.resolve` + `cltermux:access` | OAuth AT ∩ 资源服务 `{slug}:access`；300s RS256 不变；OIDC issuer 不变 |
| AP 协议 scope | （无） | 仅 `account:read` |

## 10. 撤销 outbox 语义

- unlink 在**同一短事务**内写 tombstone 与持久化撤销任务，先保证本地不可再被复活，再异步收敛远端。
- 撤销任务可重试、幂等；远端最终一致，失败不阻塞登录入口。
- tombstone 阻止延迟到达的创建/刷新复用同一 `client_binding_id`；重连必须换新 UUID。
- 消费方加密令牌包 AAD 绑定 `providerUUID + bindingID + purpose`，使跨绑定/跨用途的密文不可互换。

## 11. 旧适配器隔离细节

- 0059 之后不再保留旧 adapter 路径。新消费方模块通过 HTTP 调用提供方，**绝不**进入用户登录/Session 写入路径。
- 需要从备份恢复 0059 之前的 `linked_accounts` 行不属于本协议；没有「忽略新表即可解码旧绑定」的承诺。
- 删除旧代码路径已经发生；不要把「另立 issue 再删旧表」写成仍待做——表已经 DROP。

## 12. 配置兼容

- 新配置缺省不改变登录与 OIDC；未配置资源服务时相关 API 503，不干扰旧服务。
- 配置 revision 参与令牌/绑定的条件提交；provider 身份在有未完成 grants/operations/outbox 时不可编辑。
- 配置丢失后，已签发令牌按清理流程处理；不得因配置缺失静默放宽校验。

## 13. 回滚矩阵与运维注意

| 场景 | 行为 |
| --- | --- |
| 辰星回滚到 **0059 之前**的旧二进制 | **不能**靠「忽略新表」恢复旧绑定。0059 已 `DROP TABLE linked_accounts` 并删除 `account_providers` 设置；旧二进制会找不到定制层表/注册表。`resource_service_*` 表仍在（增量迁移保留、不删库），但旧二进制不认识它们，也不能从中还原 `linked_accounts` 行。 |
| 辰星回滚但仍运行 0059 之后的库 | 旧定制层绑定已不可用；用户须在资源服务上重新绑定。从 0059 **之前**的数据库备份恢复是唯一能找回旧 `linked_accounts` 行的办法。 |
| CL 回滚到旧二进制 | 提供方旧 auth/agent API 不变；新协议端点消失，辰星消费方按不可用处理并可重新授权 |
| 部分升级 | 两仓库各自增量；提供方新端点可达且管理员配置资源服务后才 opt-in |
| 已签发新令牌在回滚后 | 旧二进制不识别 AP 令牌包 → 消费方重新授权；不得降级为旧凭据路径 |

运维：

- 升级前若仍依赖 `linked_accounts` 行做业务判定，先确认已无生产数据，或接受绑定丢失。0059 注释写明改名时这些表尚未上线、行数为零；一旦有行，DROP 不可逆。
- 不要为了「满足旧回滚矩阵」而把 `linked_accounts` 加回来并与资源服务双写。
- 回滚辰星二进制前，不要 DROP `resource_service_*`。

## 14. 验证要点（Gate2 覆盖）

- 兑换走资源服务绑定与 `{slug}:access` 交集；`linked_accounts` 不存在。
- 匿名 Discovery 只宣布 public 资源 scope（#716）。
- 刷新并发、barrier、丢响应：不得以无效 token 覆盖已产出的新一代令牌；歧义重试只用同操作 ID。
- 撤销 tombstone 阻止延迟创建/刷新复活。
- 消费方令牌包加密 AAD = providerUUID + bindingID + purpose。
- SSRF/恶意字段：未知字段类型忽略、未知顶层字段忽略、URL 仅 HTTPS 无 userinfo。
- UI 可信渲染：无 HTML/JS/CSS 注入、不自动加载远程媒体。
- 创建/刷新操作指纹为 keyed HMAC（#717）：刷新指纹只绑 provider/binding/user，不含会旋转的 refresh token。提供方 409 `already_committed` 先探本地（#718）。同步在提供方 200 时落库 `snapshot_json`；CAS 未命中返回当前 live 行（#719）。
