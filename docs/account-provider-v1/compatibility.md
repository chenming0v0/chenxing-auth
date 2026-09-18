# Account Provider v1 — 辰星侧兼容与迁移策略

状态：**PLANNED**。本文件只描述辰星**消费方**侧的兼容与迁移策略，不含实现。

## 1. 方向与核心原则

- **提供方**（CLtermux）实现并托管协议端点；**辰星是消费方/客户端**。
- 辰星在新协议中的角色：门户采集提供方凭据 → Basic 调用提供方创建/刷新 → Bearer 调用提供方查询 → 持有可逆加密令牌包以便使用。
- **提供方端点与消费方 API 必须分清**：`/.well-known/account-provider` 与 4 个协议端点由提供方托管；辰星只新增**独立的、经认证的**管理/门户消费方 API。
- **纯增量**：新协议只增新表、新模块、新消费方 API；旧表不被通用数据污染。
- **旧契约冻结**：旧严格 `AccountAdapter` enum JSON、旧 `linked_accounts` 持久化形状保持**逐字节**形状兼容。
- **不做自动迁移**：旧 `linked_accounts` **不**保存用户卡密（`src/linked_accounts/repository.rs`），因此没有可迁移的用户凭据；旧绑定保持原样。
- **回滚安全**：旧二进制忽略新表，旧 settings/bindings 照样解码。

## 2. 数据库（辰星侧）

新增**独立**表/模块（命名草案，阶段 B 冻结）：

- provider 配置（`base_url` 与提供方 issuer origin 一致、`client_id`、`client_secret` 加密、revision）
- bindings（`client_binding_id`、provider、uid、issuer、grant generation、tombstone）
- token operations（`Idempotency-Key` 的 keyed 指纹、状态、lease）
- revocation outbox（不可变撤销任务）

约束：

- 通用 provider 数据**不**写入旧 `linked_accounts` 等旧表。
- 旧表结构、旧 JSON 列语义不变。
- 迁移必须增量、可用旧二进制忽略；回滚时**保留**增量迁移，**不**删库。
- 不提供任何自动迁移旧绑定的路径。

## 3. 模块与代码边界

- 新消费方源代码**产品中立**：不出现 `cltermux` 字样。
- 旧 adapter 隔离保存在原处，**不**参与新协议路径。
- 旧线上字段名冻结；新协议不复用旧字段语义。
- 旧 adapter 位于 `src/integrations/cltermux/`，其 `validation.rs` 已 500 行（`src-line-limit` 上限）；阶段 B 只在隔离的新模块新增，不在此基础上继续增长，改动超过 500 行的文件必须先拆分。

## 4. 管理面与 API（消费方侧）

- 新增**独立的、经认证的**通用 provider 管理端点与门户聚合/操作端点；细节在**阶段 B** 冻结并同步进 `openapi.yaml`、`docs` 与 `llms.txt` 入口。
- 旧 API 契约**不受影响**；只有外部 HTTP 契约变化时才调用 `sync-openapi`。
- 消费方在未配置 provider 时返回 `503 provider_unavailable`，不干扰旧服务；提供方自身的端点是提供方行为，不由辰星实现。

## 5. 前端

- 门户接入 UI 由 designer 在 `web/src` 实现；复用 `@chenxing/ui` 正式组件。
- 临时回退需先在两仓库登记 issue 并链接，正式组件落地后移除。
- 通用连接**只**用于资料读取；披露文案必须说明凭据会瞬时经过辰星。

## 6. 旧连接与移动端

- 旧连接入口（含移动登录）保持可用；旧移动 OIDC issuer（`APP_ISSUER`）完全不变。
- **绝不**声称通用连接自动授权移动端，也**不**静默把旧连接切换为通用连接。
- 旧移动 exchange / scope / `cltermux:access` / 300s 行为按 #714 冻结，不得改动这些线上取值。

## 7. 一致性与并发

- **解绑（unlink）**：本地 tombstone + 持久化撤销任务**原子**提交；远端重试，最终一致。
- **创建/刷新**：
  1. 短事务领取操作 + lease，**HTTP 调用提供方期间不持有 DB 锁**。
  2. 短条件提交校验：当前 session/CSRF/owner、provider 身份与 revision、uid/issuer、grant/binding generation。
  3. 在途陈旧响应不能复活已 tombstone 的绑定。
- **歧义刷新重试**：网络错误/5xx 时用**同操作 ID + 同 refresh_token** 重试以发现结果；不用新操作 ID 盲重试，不恢复旧一代。
- **本地新一代优先**：若消费方已持久化新一代令牌包，则它以本地为准覆盖重复响应；若提供方已提交而令牌包丢失，只能显式重新授权并清理。
- **账号查询网络中断不使令牌失效**。
- provider 身份（端点/客户端）在有未完成 grants/operations/outbox 时**不可编辑**。

## 8. 作用域（两套默认互不相同）

- Account Provider v1 只有 `account:read`；它**不是**辰星 OAuth 的 scope 体系，也不提供 `cltermux:access`。
- #714 只针对**辰星 OAuth 新客户端的默认作用域**（`openid`/`profile`/`email`）：把未配置的 `cltermux:access` 从**新客户端**的通用默认中移除，避免新客户端被隐式授予 legacy scope。
- 既有客户端、既有 grants、显式配置的 legacy scope、以及 exchange 300s 线上取值**全部保留不变**；**不**删除任何已存在的 grants 或已配置 scope。

## 9. 新旧产物对照（含方向）

| 产物 | 旧（冻结不变） | 新（增量） |
| --- | --- | --- |
| 数据表（辰星） | 旧 `linked_accounts` 及既有设置表 | provider 配置 / bindings / token operations / revocation outbox |
| adapter（辰星） | 严格 `AccountAdapter` enum JSON | 产品中立的通用 provider 消费方模块 |
| 配置键（辰星） | 旧应用设置与 scope | `ACCOUNT_PROVIDER_*`（提供方侧 3 键）+ 辰星后台 `base_url`/`client_id`/`client_secret` |
| 客户端密钥 | 旧应用 HS256 secret | 独立 ≥32 随机字节机密客户端，绝不复用 |
| 令牌存储 | 旧 App / mobile token | **提供方**只存 SHA256；**辰星**存可逆加密包（AAD = providerUUID + bindingID + purpose） |
| 提供方端点 | 旧 auth/agent API | 提供方托管 `/.well-known/account-provider` + 4 个协议端点（**非辰星实现**） |
| 消费方 API | 旧管理端点 | 辰星新增独立、经认证的管理/门户消费方 API |
| 错误 | 旧错误结构 | `{error:{code,message,retryable,request_id}}` |
| 移动端 | 旧 exchange / `cltermux:access` / 300s / OIDC issuer | **零变化** |

## 10. 撤销 outbox 语义

- unlink 在**同一短事务**内写 tombstone 与持久化撤销任务，先保证本地不可再被复活，再异步收敛远端。
- 撤销任务可重试、幂等；远端最终一致，失败不阻塞旧连接入口。
- tombstone 阻止延迟到达的创建/刷新复用同一 `client_binding_id`；重连必须换新 UUID。
- 消费方加密令牌包 AAD 绑定 `providerUUID + bindingID + purpose`，使跨绑定/跨用途的密文不可互换。

## 11. 旧适配器隔离细节

- 旧 adapter 模块保留原路径、原类型、原 JSON 标签；新协议**不**复用其类型，避免旧严格 enum 解析器被通用数据撑爆。
- 新消费方模块通过 HTTP 调用提供方，**绝不**进入辰星旧 `linked_accounts` 绑定/交换路径或用户登录/Session 写入路径，也不复用旧 adapter 的编解码。
- 旧线上字段名（含 `subscription`、`device`、`extensions`）冻结；新增语义只在辰星新协议里表达。
- 删除旧代码路径不属于本次变更；需要废弃时另立 issue。

## 12. 配置兼容

- 新配置缺省不改变旧行为；未配置 provider 时 503，不干扰旧服务。
- 配置 revision 参与令牌/绑定的条件提交；provider 身份在有未完成 grants/operations/outbox 时不可编辑。
- 配置丢失后，已签发令牌按清理流程处理；不得因配置缺失静默放宽校验。

## 13. 回滚矩阵

| 场景 | 行为 |
| --- | --- |
| 辰星回滚到旧二进制 | 忽略新表；旧 settings/bindings 正常解码；保留增量迁移，不删库 |
| CL 回滚到旧二进制 | 提供方旧 auth/agent API 不变；新协议端点消失，辰星消费方按不可用处理并可重新授权 |
| 部分升级 | 两仓库各自增量；提供方新端点可达后才 opt-in |
| 已签发新令牌在回滚后 | 旧二进制不识别 → 消费方重新授权；不得降级为旧凭据路径 |

## 14. 验证要点（Gate2 覆盖）

- 辰星旧 adapter 配置/绑定 JSON、旧移动 exchange + scope、旧 OIDC issuer 均存活。
- 刷新并发、barrier、丢响应：不得以无效 token 覆盖已产出的新一代令牌；歧义重试只用同操作 ID。
- 撤销 tombstone 阻止延迟创建/刷新复活。
- 消费方令牌包加密 AAD = providerUUID + bindingID + purpose。
- SSRF/恶意字段：未知字段类型忽略、未知顶层字段忽略、URL 仅 HTTPS 无 userinfo。
- UI 可信渲染：无 HTML/JS/CSS 注入、不自动加载远程媒体。
