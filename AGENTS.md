# AGENTS.md

## 项目概述

本项目是“天穹辰星 · 辰星认证中枢”，用户侧产品为“辰星通行证”。它是一个计划中的、独立运行的 Rust 登录认证平台，目标技术栈为：

- Rust
- Axum
- PostgreSQL
- Redis
- OAuth 2.0 / OpenID Connect
- JWK / JWKS 密钥管理

当前仓库处于后端能力建设和部署自动化阶段，已有 Rust/Cargo 配置和可编译的 Axum 服务。健康检查、账号注册/登录、浏览器登录与授权确认、Redis Session、HttpOnly Cookie/CSRF、Client 生命周期、OIDC Discovery、JWKS 多版本轮换、PKCE、带 nonce 的授权码、Access Token、ID Token、Refresh Token、UserInfo、Token 撤销、审计、管理员身份/角色/Session、用户与 Client 管理 API、Docker 生产部署和 GitHub Actions 多平台构建流程已经实现；完整视觉化管理后台和广泛第三方互操作仍未完成。实现新功能前，先确认目标是否已经落入现有架构和数据边界；不要把规划文档中的能力当作已实现能力。

认证中枢独立于天穹辰星的其他子项目平台，专门负责账号、登录认证、OAuth/OIDC 授权、会话和身份信息服务。天穹辰星其他子项目是认证平台的接入方，应通过 Client 接入，不应把各自的业务功能或业务数据直接并入认证平台。

辰星通行证账号在本平台创建后，可用于注册和登录已接入的天穹辰星子项目。接入方负责自己的业务账号绑定、角色、权限、资料和业务数据；认证平台负责用户身份事实和协议授权边界。不要假设认证平台可以直接读取或管理接入方的业务状态。

## 设计原则

### 标准优先，业务适配其次

OAuth 2.0、OIDC、JWT、JWK/JWKS 和密码学相关能力优先使用成熟的 Rust 库。不要自行实现密码学算法、令牌签名、协议解析或安全敏感的编码逻辑，除非有经过评审的明确理由。

业务代码负责：

- 用户生命周期和凭据策略
- OAuth Client 生命周期和接入策略
- 登录与授权确认交互
- Session 生命周期和撤销
- 管理员权限、审计和业务扩展

子项目接入通过 OAuth 2.0 / OIDC Client 完成。新增接入能力时，优先设计标准协议和明确 Claims，不为单个子项目硬编码业务逻辑；确有业务扩展需求时，放入隔离的扩展接口，并明确数据所有权和权限边界。

### 清晰的分层

目标分层如下：

1. HTTP 表现层：Axum 路由、提取器、响应和协议错误映射。
2. 应用层：用例编排、事务边界和权限检查。
3. 领域层：用户、Client、授权、会话、密钥和管理领域规则。
4. 基础设施层：PostgreSQL、Redis、密钥存储和外部服务适配。

领域层和应用层不应依赖 Axum 的请求类型、Redis 具体客户端或 SQL 查询细节。使用 trait 定义必要的存储和服务边界，便于单元测试和替换实现。

### 数据职责

- PostgreSQL 保存用户、Client、授权关系、密钥元数据、管理员和审计等持久化事实。
- Redis 保存 Session、授权码、State、PKCE 相关短期状态、限流状态和可失效缓存，并设置 TTL。
- 敏感值不写入普通日志；令牌、Client Secret、会话 Cookie 和授权码必须按凭据处理。
- 数据库变更使用可审查、可回滚策略清晰的迁移文件，不在应用启动时静默修改生产结构。

## 安全要求

提交认证相关代码前，必须检查以下事项：

- 密码使用合适参数的慢哈希，禁止明文和可逆存储。
- 授权码短时有效、单次使用，并绑定 Client、Redirect URI 和用户会话。
- 授权码和 Refresh Token 必须在绑定、过期和 PKCE 检查通过后原子消费，避免错误请求烧掉有效凭据。
- 支持 PKCE 时必须正确校验 `code_verifier`，不得绕过校验。
- Redirect URI 必须经过严格校验，禁止未经设计的任意通配。
- Session、State、Nonce、授权码和刷新令牌必须具备明确的生命周期和撤销行为。
- Cookie 根据场景设置 `Secure`、`HttpOnly` 和合适的 `SameSite` 属性。
- 管理接口执行认证、授权和最小权限检查，并记录关键变更审计。
- JWK 私钥不得通过 API 或日志暴露；密钥轮换时保留必要的旧公钥验证窗口。
- `KEY_DIRECTORY` 下的私钥和 `kid` 文件属于运行时秘密材料，必须保持在 Git 忽略范围内；生产环境应替换为受保护的密钥存储。
- 错误响应不能泄露密码、令牌、密钥、SQL、堆栈或内部网络信息。
- 新增依赖前检查维护状态、许可证、已知漏洞和是否已有成熟项目内替代方案。

安全边界不明确时，先暂停实现并补充设计或测试，不要凭直觉放宽校验。

## 代码约定

- 遵循 Rust 官方格式和 Clippy 建议；提交前运行 `cargo fmt --check` 和 `cargo clippy --all-targets --all-features -- -D warnings`（项目具备 Cargo 配置后）。
- 错误类型按边界区分，避免在业务层到处使用字符串错误或 `unwrap()`。
- 对用户输入使用结构化类型和显式校验；不要使用脆弱的字符串拼接构造 SQL、URL 或协议响应。
- 异步函数不得执行未隔离的阻塞操作；数据库和 Redis 访问应通过清晰的异步接口完成。
- 路由处理器保持薄，只做提取、调用用例和响应转换。
- 日志使用结构化字段，避免记录敏感值；为认证失败、授权失败和管理员操作保留可检索上下文。
- 公共接口、配置项、迁移和协议行为应同步更新文档和测试。
- 代码注释解释原因、协议约束或安全边界，不重复描述显而易见的代码。
- `APP_ISSUER` 是 OIDC 发行者标识，不能从请求 Host 或反向代理输入推导；Discovery、JWT Claims 和后续协议响应必须使用同一配置值。
- 当前 OAuth 授权端点的 Session 头部是开发期兼容方式；生产浏览器应使用登录页签发的 HttpOnly Cookie 和授权确认页。
- `ADMIN_TOKEN` 为空时必须拒绝所有已初始化的管理员 API；唯一例外是 `admins` 表为空时公开的首个管理员初始化接口。Client Secret 只能在创建时返回，后续列表和查询不得返回哈希或明文。
- 签名密钥轮换必须共享 AppState 克隆的密钥状态，按 JWT `kid` 选择验证公钥；管理员响应不得包含私钥材料。
- 浏览器 Cookie 会话的状态变更必须校验 HttpOnly Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 三者绑定；开发期请求头兼容逻辑不能成为生产浏览器认证方案。
- 管理员角色必须通过 `AdminPermission` 校验；管理员 Session 的写操作必须校验独立的管理员 CSRF Cookie 和 `X-CSRF-Token`。

## 测试要求

按风险选择测试层级：

- 领域规则用单元测试覆盖，包括用户状态、Client 校验、Scope、Redirect URI 和会话生命周期。
- OAuth/OIDC 流程用集成测试覆盖，包括成功流程、PKCE、State/Nonce、错误流程、重复使用和过期场景。
- PostgreSQL 和 Redis 适配器使用真实服务或可靠的容器化测试环境验证，不仅依赖过度简化的 Mock。
- 管理后台覆盖权限隔离、审计记录和敏感字段脱敏。
- 密钥轮换覆盖新旧 JWK 的发布与验证过渡。
- 修复缺陷时先增加能够复现问题的测试，再修改实现。
- 新增部署和 CI 能力必须同时验证脚本语法、Compose 配置、Action 文件结构、发布产物/校验和声明和覆盖率门槛；不能只验证 Rust 编译。

完成任何代码变更后，必须使用项目级 `src-line-limit` skill 检查 `src` 目录：

- 超过 300 行的文件属于弱警告，必须在变更说明中记录。
- 超过 500 行的文件属于强警告，完成前必须拆分或重构；除非用户明确接受例外，不得声称任务完成。

项目拥有 Cargo 配置后，常规验证命令为：

```powershell
cargo fmt --check
cargo check --all-targets --all-features
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info --fail-under-lines 75
cargo audit
```

本机快速运行测试可安装并使用 `cargo-nextest`。它会并行调度不同的测试二进制；`cargo test -- --test-threads` 只控制单个测试二进制内部的线程，不能并行化多个 `tests/*.rs` 测试进程：

```powershell
cargo install cargo-nextest --locked
cargo nextest run --all-features --test-threads 32
```

`cargo-nextest` 是本地加速工具，不替代标准 `cargo test` 的通用验证命令；CI 使用 Runner 默认资源，不要硬编码本机的 32 线程。

本机编译性能基准：热缓存下 `cargo check --all-targets --all-features` 和 `cargo test --all-features --no-run` 通常应接近亚秒级；冷编译全部测试目标约需几十秒，主要成本来自 `aws-lc-sys`、`ring`、`sqlx` 等依赖和测试二进制链接。日常开发优先使用：

```powershell
cargo check --all-targets --all-features
cargo nextest run --all-features --test-threads 32
```

不要同时启动多个 Cargo 编译或测试命令；它们会争抢 package cache 和 target build lock，导致耗时明显增加。

如果某个命令暂时因工具链或外部服务不可用而无法运行，必须在变更说明中明确记录原因，不要声称验证通过。

### 分支工作流

- 本项目的主要开发分支是 `dev`。用户未明确指定分支、说“主要分支”或要求合并到主线时，默认使用 `dev`，不要自行使用已废弃的 `master`。
- `releases` 是释放分支，仅在变更已经在 `dev` 验证通过、准备发布或用户明确要求“释放分支”时使用。
- 功能分支应从当前明确的目标基线创建；开始工作前必须检查当前分支、工作区状态、远端跟踪关系以及目标分支的祖先关系，确认没有把功能分支误合入 `dev` 或 `releases`。
- 涉及分支合并、推送、删除或发布时，先向用户确认目标分支语义；“主要分支”表示 `dev`，“释放分支”明确表示 `releases`。
- 删除或改写分支前必须先确认提交已安全存在于正确的远端分支，并保留必要的恢复引用；禁止未经确认删除远端分支或执行强制推送。

## 当前仓库状态

后端已形成按用户、Client、OAuth、Session、密钥、审计和管理边界拆分的模块结构。新增实现应先更新受影响的约定、迁移和测试，再开始跨模块修改；规划中的前端和生产运维能力不能被描述为已完成。

首次打开 Web 前端时，应用必须先查询管理员初始化状态。`admins` 表为空时显示初始化界面，提交用户名和密码后通过公开初始化接口创建唯一的首个 Owner 管理员；初始化使用 PostgreSQL advisory lock 保证并发请求最多成功一次。普通用户和管理员都使用从 `1` 开始递增的整数 ID 作为主键，二者序列独立，首个初始化管理员的 ID 固定为 `1`。管理员用户名不要求邮箱，初始化成功只显示成功提示并跳转管理员登录页，不自动创建管理员 Session。管理员已存在时不得再次公开创建，必须使用管理员用户名登录和已授权的管理接口。需要重新初始化时，由维护人员清理数据库后再重新执行初始化流程

## API Wiki 与 OpenAPI

- 后端 API 的可导入契约文件是仓库根目录的 `openapi.yaml`，前端接入和 Apifox 项目应以它为准。
- API Wiki/LLM 文档入口为 `https://wiki.auth.clya.top/llms.txt`；对外 API 文档发布后应保持该入口与当前接口契约一致。
- 新增、删除或修改任何后端 HTTP 路由、请求参数、响应结构、错误码或鉴权方式后，必须调用项目级 `sync-openapi` skill，同步更新 `openapi.yaml`。
- 更新后必须验证 YAML/OpenAPI 基础结构，并确认接口分组、`operationId`、Security Scheme、请求体和响应模型没有遗漏；不能只更新 `API.md`。
- Apifox 导入建议开启“自动生成调试用例”“导入 Security Scheme”和“将 Servers 导入为环境”；无 Security 的接口保持无需鉴权。
- GitHub Actions 的 `apifox-sync` Job 在 `dev` 质量检查通过后，使用仓库 Environment Secret `API_FOX_KEY` 将 `openapi.yaml` 自动导入 Apifox 项目 `8642631`；不要在工作流、日志或提交中写入该密钥。
