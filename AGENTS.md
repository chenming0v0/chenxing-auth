# AGENTS.md

## 项目概述

本项目是“天穹辰星 · 辰星认证中枢”，用户侧产品为“辰星通行证”。它是一个计划中的、独立运行的 Rust 登录认证平台，目标技术栈为：

- Rust
- Axum
- PostgreSQL
- Redis
- OAuth 2.0 / OpenID Connect
- JWK / JWKS 密钥管理
- React / Vite（前端，源码位于 `web/src`，开发端口固定为 5175）

## 设计原则

### 重要!!!!

- 你的任务不是快速的完成代码任务而是设计我们的项目，不要老是想着最小改动，在该大重构的时候应该大胆大步走，如果你只改动这一点会导致之后的维护更不容易的话！请你直接处理他！而不是一个最小改动，现在项目处于早期版本，放手去改吧！不要被最小改动束缚住！

### 清晰的分层

目标分层如下：

1. HTTP 表现层：Axum 路由、提取器、响应和协议错误映射。
2. 应用层：用例编排、事务边界和权限检查。
3. 领域层：用户、Client、授权、会话、密钥和管理领域规则。
4. 基础设施层：PostgreSQL、Redis、密钥存储和外部服务适配。

领域层和应用层不应依赖 Axum 的请求类型、Redis 具体客户端或 SQL 查询细节。使用 trait 定义必要的存储和服务边界，便于单元测试和替换实现。

### 数据职责

- PostgreSQL 保存用户、Client、授权关系、密钥元数据和审计等持久化事实。
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
- `ADMIN_TOKEN` 为空时必须拒绝所有已初始化的管理 API；唯一例外是不存在 Owner 时公开的首个 Owner 初始化接口。Client Secret 只能在创建时返回，后续列表和查询不得返回哈希或明文。
- 签名密钥轮换必须共享 AppState 克隆的密钥状态，按 JWT `kid` 选择验证公钥；管理员响应不得包含私钥材料。
- 浏览器 Cookie 会话的状态变更必须校验 HttpOnly Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 三者绑定；开发期请求头兼容逻辑不能成为生产浏览器认证方案。
- 管理角色必须通过 `AdminPermission` 校验；管理 Session 的写操作必须校验普通 HttpOnly Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。

### 前端与端口约定

- 前端统一使用 React，源码位于 `web/src`，构建由 `web` 下的 Vite 完成；新增或修改页面只改动 `web/src` 下的 React 代码。
- 禁止在 Rust 中生成或渲染 HTML 页面（包括服务端模板、字符串拼接 HTML 等）；所有页面、路由和交互一律由 React 实现。
- 后端仅允许静态托管 React 构建产物（`web/dist`）用于单二进制部署，不得输出自定义 HTML 页面或服务端渲染内容；修改前端后必须重新构建 `web/dist` 以同步内嵌产物。
- 前端开发统一使用 Vite 开发服务器，端口固定为 `5175`，不允许漂移到其他端口；后端 API 端口由 `APP_PORT` 配置决定（默认 `3000`），Vite 通过 `/api` 和 `/health` 代理访问后端。

### 设计稿与 Web UI 修改

- 原型设计稿（`design-auth-chengming/`）和设计稿专用的 `design-canvas-format` skill 只存在于 `design` 分支，不在 `dev` 和 `releases` 中；不要在 `dev` 上重新添加它们。
- 需要查阅或修改设计稿时，不要切换当前工作区分支，使用独立 worktree：`git worktree add ../chenxing-auth-design design`。
- 设计稿改动只在 `design` 分支提交；`design` 单向从 `dev` 接收更新，禁止把 `design` 合并或 cherry-pick 回 `dev` / `releases`。
- 新增或修改任何卡片、玻璃容器、表单面板等 UI 时，必须使用项目级 `chenxing-hud-panel` skill 指定的公共容器 `.chenxing-hud-panel`，并通过 `web/src/components/ui.tsx` 的 `HudPanel` 组件渲染；禁止另建玻璃卡片样式或复用旧的 `chenxing-glass-strong chenxing-hud-frame` 组合。
- 面板样式的唯一来源是 `web/src/chenxing-design.css`，不要复制到其他 CSS 或组件内联样式。

## 测试要求

按风险选择测试层级：

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
- `design` 是设计稿分支，只保存 `design-auth-chengming/` 和设计稿专用 skill；它单向从 `dev` 接收更新，禁止合并回 `dev` 或 `releases`。
- 功能分支应从当前明确的目标基线创建；开始工作前必须检查当前分支、工作区状态、远端跟踪关系以及目标分支的祖先关系，确认没有把功能分支误合入 `dev` 或 `releases`。
- 涉及分支合并、推送、删除或发布时，先向用户确认目标分支语义；“主要分支”表示 `dev`，“释放分支”明确表示 `releases`。
- 删除或改写分支前必须先确认提交已安全存在于正确的远端分支，并保留必要的恢复引用；禁止未经确认删除远端分支或执行强制推送。

## API Wiki 与 OpenAPI

- 后端 API 的可导入契约文件是仓库根目录的 `openapi.yaml`，前端接入和 Apifox 项目应以它为准。
- API Wiki/LLM 文档入口为 `https://wiki.auth.clya.top/llms.txt`；对外 API 文档发布后应保持该入口与当前接口契约一致。
- 新增、删除或修改任何后端 HTTP 路由、请求参数、响应结构、错误码或鉴权方式后，必须调用项目级 `sync-openapi` skill，同步更新 `openapi.yaml`。
- 更新后必须验证 YAML/OpenAPI 基础结构，并确认接口分组、`operationId`、Security Scheme、请求体和响应模型没有遗漏；不能只更新 `API.md`。
- Apifox 导入建议开启“自动生成调试用例”“导入 Security Scheme”和“将 Servers 导入为环境”；无 Security 的接口保持无需鉴权。
- GitHub Actions 的 `apifox-sync` Job 在 `dev` 质量检查通过后，使用仓库 Environment Secret `API_FOX_KEY` 将 `openapi.yaml` 自动导入 Apifox 项目 `8642631`；不要在工作流、日志或提交中写入该密钥。
