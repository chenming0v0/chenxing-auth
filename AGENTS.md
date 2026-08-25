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
- 首个 Owner 初始化接口匿名公开且采用“先到先得”是项目明确接受的风险，不要求额外 setup secret、CLI 或本机访问证明。未初始化实例若被抢注，运维通过清空并重建数据库重新初始化；架构审查和安全审查不得将该既定行为重复报告为缺陷或创建 Issue，除非项目所有者明确改变这一策略。
- 签名密钥轮换必须共享 AppState 克隆的密钥状态，按 JWT `kid` 选择验证公钥；管理员响应不得包含私钥材料。
- 浏览器 Cookie 会话的状态变更必须校验 HttpOnly Session Cookie、CSRF Cookie 和 `X-CSRF-Token` 三者绑定；开发期请求头兼容逻辑不能成为生产浏览器认证方案。
- 管理角色必须通过 `AdminPermission` 校验；管理 Session 的写操作必须校验普通 HttpOnly Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。
- 浏览器会话默认策略：`SESSION_TTL_SECONDS` 与 `SESSION_IDLE_TIMEOUT_SECONDS` 部署默认均为 1209600 秒（14 天），产品意图是让用户长期免登录；不得把 idle 默认改回短窗口。已签发会话的 idle 窗口在签发时固化（#644），修改设置只影响新会话。

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

### 变更验收

- 完成任何代码变更后，必须使用项目级 `src-line-limit` skill 检查 `src` 目录：超过 300 行属弱警告，必须在变更说明中记录；超过 500 行属强警告，完成前必须拆分或重构，除非用户明确接受例外，不得声称任务完成。
- 新增部署和 CI 能力必须同时验证脚本语法、Compose 配置、Action 文件结构、发布产物/校验和声明和覆盖率门槛；不能只验证 Rust 编译。

## 测试与验证

本节规定两件事：跑测试用什么工具，谁能跑哪些命令。

核心约束一句话——验证强度按执行角色和变更风险分层。全量套件是需要用户授权的一次性动作，不是每个子任务的默认收尾。

### 测试工具

判定标准只有一条：命令是否实际执行 `#[test]` 用例。执行的，走脚本；不执行的，不受限制。

#### 不执行用例的命令

日常开发反馈，改完就跑，任何角色无限制：

```bash
cargo fmt --check
cargo check --all-features
```

需要确认测试目标能编译时，用 `cargo check --tests` 或 `cargo check --all-targets`。这两个只编译不跑用例，同样无限制。默认优先 `cargo check`，确有需要再扩大范围。

`cargo check` 是开发反馈的第一道检查，但它不替代运行时测试。

#### 测试脚本 `test_sh/test.sh`

要执行用例，统一走这个脚本。它做三件裸 Cargo 命令做不到的事：

- 通过的用例不进终端，只输出失败和汇总，避免污染上下文。完整输出始终落在 `target/test-logs/<时间戳>/`，需要时按路径查看。
- 报告分阶段耗时与总耗时。
- 结束后自动剪枝 `target` 里陈旧的测试二进制。

模式与耗时：

| 模式 | 作用 | 耗时 |
| --- | --- | --- |
| `--lib` | 只跑单元测试，不连数据库 | 约 6 秒 |
| `--test NAME` | 只跑指定集成测试目标，可重复 | 约 5 秒 |
| `--clean-only` | 只清理陈旧产物，不编译不测试 | — |
| `--full` | 完整套件 | 约 2-4 分钟 |
| `--gate` | 完整验证链：check、测试、clippy、覆盖率、audit | — |
| `--coverage` | 仅覆盖率门槛，行覆盖 75% | — |
| `--clippy` | 仅 `clippy -D warnings` | — |
| `--audit` | 仅 `cargo audit` | — |

不带模式裸调用会以退出码 2 失败，不存在隐式的默认全量。

后五个模式加 `-E / --filter` 属于编排者专属，需按次内联传入角色变量：

```bash
CHENXING_TEST_ROLE=orchestrator ./test_sh/test.sh --full
```

单目标集成测试可以连 PostgreSQL / Redis。当前显式目标为 `admin`、`auth`、`identity`、`oauth`、`platform`、`storage`。`tests/support/db_isolation.rs` 提供 per-test schema 隔离，成本和风险都远低于全量套件。

脚本分三个文件：`test.sh`（参数解析、角色门控、模式分发）、`lib.sh`（计时、汇总表、日志、服务探测）、`phases.sh`（各验证阶段）。后两个由 `test.sh` source，不单独执行。

#### 为什么必须剪枝 target

`deps/` 下的文件名是 `名字-<hash>`，hash 由 feature 组合、profile、依赖版本、rustc 版本共同决定。任何一项变化都会产出一份新产物，而旧的不会被删除。本项目将集成测试收口为 6 个显式测试目标、每个约 242 MiB（其中 98% 是调试信息），因此每换一套编译配置就多占约 1.5 GiB；测试用例总数不因收口而减少。

`test_sh/prune_target.py` 依据 Cargo 自己报告的 `compiler-artifact` 清单判定哪些产物还活着，只删陈旧配置的残留。受限编译（`--lib` / `--test`）下退化为同名去重，并用 mtime 窗口保留同一次构建的多个合法产物。

`--coverage` 会用独立的 `target/llvm-cov-target` 从零重编译，并通过 `cargo llvm-cov nextest` 按进程隔离跑用例（与 quality job 同一模型，避免共享进程里的 `HTTP_PROXY` 泄漏），运行器在覆盖率阶段结束后顺带剪枝该目录。

#### 会执行用例的裸 Cargo 命令

`cargo test`、`cargo nextest run`、`cargo llvm-cov` 都执行用例。默认不使用，唯一例外见「编排者」。

### 权限

#### 所有角色

执行用例一律通过 `test_sh/test.sh`。不执行用例的 `fmt` / `check` 不受限。

`CHENXING_TEST_ROLE` 必须按次内联传入，禁止 `export`。一旦导出，派生的子代理会继承编排者权限，门控就失效了。

不要同时启动多个 Cargo 编译或测试命令，它们会争抢 package cache 和 target build lock，导致耗时明显增加。

如果某个命令因工具链或外部服务不可用而跑不起来，在变更说明中写明原因，不要声称验证通过。

角色变量是防误触的护栏，不是安全边界，子代理自己也能设。真正的权威是本节规则。运行器每次会把生效角色和模式打在第一行，越权痕迹在对话记录里可查。

#### 子代理

**禁止子代理执行任何会产生 `target/` 文件的命令。** 子代理只能运行不触发编译的命令。`cargo check`、`cargo test`、`cargo build`、`cargo clippy` 等一切涉及编译入口的命令全部禁止——它们生成的 `target/` 目录（每个约 5-20 GB）是工作树膨胀的元凶，且子代理的产物不会被自动清理。

允许：`cargo fmt --check`（不编译，不产生 `target/`）。

禁止：

- 任何会产生 `target/` 文件的命令，包括但不限于 `cargo check`、`cargo build`、`cargo test`、`cargo clippy`、`cargo llvm-cov` 以及它们的任何变体。
- 任何 `test.sh` 调用——脚本本身调用 `cargo test` 或 `cargo llvm-cov`，必然产生 `target/`。
- `-E / --filter`。`-E 'all()'` 等于全量套件，会绕过门控。
- 绕过运行器直接调用裸 Cargo 测试命令。

#### 编排者

`--clippy`、`--audit` 不执行用例，无需授权可直接跑；但它们在运行器里仍属编排者专属模式，同样要按次内联传入 `CHENXING_TEST_ROLE=orchestrator`。

`--full`、`--gate`、`--coverage` 属于全量，必须先取得用户明确同意：

- 只有在改动数据库、迁移、SQL repository、Redis/session 持久化、OAuth 端到端流程或并发持久化逻辑时，才向用户请求授权。
- 请求时机是最终修复完成之后。先把代码改完，静态检查和聚焦编译过了，再问。
- 一次授权只对当次这一次运行有效，不延伸到后续任务、子代理或覆盖率命令。
- 全量跑出问题由编排者按日志继续修复，不转交子代理反复跑全量。
- 本地不跑全量时，这类改动的数据库集成测试由 CI 覆盖。

同一次授权内，如果确实需要裸命令复现特定失败，可以用 `cargo test --all-features` 或 `cargo nextest run --all-features` 替代 `--full`，同样只跑一次。这是授权后的替代形式，不是独立权限；未授权时它和 `--full` 一样禁止。同一授权下可按需 `cargo install cargo-nextest --locked`，它并行调度不同测试二进制，而 `cargo test -- --test-threads` 只控制单个二进制内部的线程。

## 分支工作流

- 本项目的主要开发分支是 `dev`。用户未明确指定分支、说“主要分支”或要求合并到主线时，默认使用 `dev`，不要自行使用已废弃的 `master`。
- `releases` 是释放分支。
- `releases` 不接受任何直接提交，只接受来自其他分支的合并。发现自己即将在 `releases` 上提交时，不要停下询问：自觉切回 `dev` 再提交，并顺口告诉用户一句他忘记切分支了。这条自主切换分支的权限仅限“当前确实要提交、且提交目标是 `releases`”这一种情形，其他分支切换仍需用户确认。
- 把 `dev` 合并到 `releases` 之前，必须先在 `dev` 上把 `Cargo.toml` 的 `version` 改成本次要发布的版本号，并同步 `Cargo.lock` 里 `chenxing-auth` 的版本和 `.github/workflows/release-tag.yml` 的 `default`。版本号提交在合并之前完成，让标签 `vX.Y.Z` 与它指向的提交自身声明的版本一致；不要合并完再补。
- 打标签是发布链的关键一步，只能使用能触发下游工作流的凭据。GitHub 有防递归规则：用默认 `GITHUB_TOKEN` 推送的标签不会触发任何新的工作流运行。`Create Release Tag` 工作流（release-tag.yml）曾经用 `GITHUB_TOKEN` 推标签，结果是标签存在、但 Build And Publish 的 `Publish release assets` job（条件 `if: startsWith(github.ref, 'refs/tags/v')`）永不执行，GitHub Release 不会生成——表现为"工作流都成功了却没有 Release"。因此打标签二选一：
  1. 本地推送（推荐，最稳）：合并后本地 `git tag -a vX.Y.Z -m "release: vX.Y.Z"` 并用个人凭据 `git push origin vX.Y.Z`，与 v1.1.0 及之前的流程一致。
  2. 工作流触发：先确保仓库已配置 `RELEASE_PAT` secret（细粒度 PAT，`Contents: Read and write` 权限），否则 release-tag.yml 会显式失败并提示。该工作流用 PAT 推标签才能触发下游 Build And Publish。
- 合并 dev 到 releases 后看到 CI 和 Build And Publish 都成功，**不等于发布完成**：分支 push 触发的那次运行不含 `Publish release assets` job（该 job 只响应 tag push）。必须确认远端存在 `vX.Y.Z` 标签且 Build And Publish 有 tag 事件的运行（`gh run list --workflow=321905998 --json headBranch,event` 里 headBranch 为 vX.Y.Z 的 push 运行）后，GitHub Release 才会出现在列表。
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
