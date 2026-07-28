# 天穹辰星 · 辰星认证中枢

<div align="center">
<img style="width:70%" src="https://count.getloli.com/@chenxing-auth?name=chenxing-auth&theme=booru-lewd&padding=6&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="chenxing-auth visit count">
</div>

辰星认证中枢是独立运行的登录认证平台，面向天穹辰星各子项目平台及其他受信任应用提供统一身份认证能力。它在产品、服务和数据边界上独立于天穹辰星的其他业务平台，不承载具体子项目的业务功能。

用户侧产品名称为 **辰星通行证**。用户创建辰星通行证账号后，可以使用该账号注册和登录天穹辰星的其他子项目平台。平台提供统一登录、OAuth 2.0 / OpenID Connect（OIDC）授权、用户与 Client 管理、会话管理，以及隔离的业务扩展接口。

当前仓库以可运行的后端和部署能力为主，前端优先级较低。浏览器登录、授权确认、管理员账号会话、角色权限、用户/Client/审计管理 API、OAuth/OIDC 授权码流程和 Docker/GitHub Actions 已实现；完整视觉化管理后台和第三方互操作认证矩阵仍属于后续增强项。

## 项目定位

- **品牌**：天穹辰星
- **平台**：辰星认证中枢
- **用户产品**：辰星通行证
- **全称**：天穹辰星 · 辰星认证中枢
- **许可证**：MIT License

平台的核心目标是让各子项目和外部应用通过标准协议接入独立的统一身份体系：用户只需维护一套辰星通行证账号，即可在不同接入平台间使用；各接入平台仍独立维护自己的业务资料、权限和业务数据。认证平台自身只负责身份、认证、授权和相关安全能力，不直接管理子项目业务。

## 目标能力

### 认证与授权

- OAuth 2.0 授权能力
- OpenID Connect 身份层
- 授权码流程，以及在明确安全边界后支持其他必要流程
- 用户信息（UserInfo）与标准化 Claims
- OIDC nonce 绑定与 RS256 ID Token
- JWK / JWT 密钥发布与轮换
- 登录页面和授权确认页面
- Scope、Redirect URI、Client 类型和授权策略校验

协议实现优先复用成熟、经过审计或广泛使用的 Rust 协议库；业务代码负责平台自身的用户、Client、授权策略和生命周期管理，不重复实现密码学算法、JWT 签名或 OAuth/OIDC 基础协议细节。

### 平台管理

- 用户注册、登录、资料和状态管理
- Client 注册、凭据、Redirect URI、Scope 和状态管理
- 管理后台
- 管理员权限和操作审计
- 会话撤销、过期和设备管理
- 面向业务系统的可扩展认证能力

### 跨平台账号使用

- 辰星通行证账号在认证平台统一创建和管理
- 天穹辰星其他子项目通过注册为 OAuth/OIDC Client 接入
- 子项目可使用辰星通行证完成注册、登录和身份绑定
- 子项目的业务账号、业务权限和业务数据由子项目自身维护
- 认证平台与子项目之间通过标准 Claims 和明确的 Client 授权边界交换身份信息

### 基础设施

- Rust 应用服务
- Axum HTTP API
- PostgreSQL 持久化用户、Client、授权和审计数据
- Redis 保存短期状态、会话和可失效缓存
- JWK 密钥存储、发布、轮换和撤销策略

## 目标架构

```text
浏览器 / 子项目平台 / 第三方应用
        |
        v
   Axum API
        |
        +--> OAuth 2.0 / OIDC 协议层 ----> 登录与授权确认页面
        |
        +--> 用户与 Client 管理 ---------> PostgreSQL
        |
        +--> Session / Redis ------------> Redis
        |
        +--> JWK 密钥管理 ---------------> 密钥存储与 JWKS 发布
        |
        +--> 管理后台与业务扩展

天穹辰星其他子项目属于认证平台的接入方，通过 Client 配置和 OAuth/OIDC 协议使用辰星通行证；它们不是认证平台的内部业务模块。
```

主要代码边界如下：

```text
src/
├── api/          Axum 路由、请求提取、响应和错误映射
├── auth/         登录、授权、用户身份和权限领域逻辑
├── oauth/        OAuth 2.0 / OIDC 协议适配与流程编排
├── users/        用户、凭据和用户状态管理
├── clients/      OAuth Client 注册与配置管理
├── sessions/     会话生命周期、Redis 存储和撤销
├── keys/         JWK/JWKS、签名密钥轮换和发布
├── admin/        管理后台 API 与管理权限
├── extensions/   业务扩展接口
├── db/           PostgreSQL 查询、迁移和事务边界
└── config/       配置加载与启动校验
```

协议层、领域服务、基础设施和 HTTP 表现层应保持可替换。领域逻辑不应直接依赖 Axum 请求对象、Redis 客户端或数据库连接细节。

## 数据与安全原则

- 密码只保存经过适当参数配置的慢哈希，禁止保存明文或可逆加密密码。
- Client Secret、会话标识、授权码和刷新令牌按敏感凭据处理，日志中不得输出原值。
- 授权码、状态值和 PKCE 校验必须绑定正确的 Client、Redirect URI、用户会话和有效期。
- Redirect URI 采用精确匹配或经明确设计的安全匹配策略，禁止任意通配。
- 管理后台默认采用最小权限原则，并保留关键操作审计记录。
- 会话和短期授权状态优先使用 Redis，并设置明确 TTL；持久化事实以 PostgreSQL 为准。
- 签名密钥支持多版本轮换，JWKS 发布保留旧公钥并按 JWT `kid` 验证过渡期令牌；私钥只保存在受保护的密钥卷中。
- 所有外部输入都必须经过结构化校验；错误响应不得泄露凭据、内部堆栈或敏感配置。
- 生产环境必须使用 TLS，并通过配置或密钥管理系统注入敏感配置。

安全相关实现应优先采用成熟库和标准安全实践，并为授权流程、会话失效、密钥轮换和权限边界补充自动化测试。

## 当前开发状态

当前已完成：

- Axum 服务入口和 `/health` 健康检查
- 环境配置加载与启动校验
- PostgreSQL 连接池边界和初始迁移
- Redis Client 边界
- 用户注册输入校验和 Argon2 密码哈希
- `POST /api/v1/users` 基础注册接口
- `POST /api/v1/auth/login` 登录并创建 Redis Session
- RSA 2048 位签名密钥生成和 JWKS 发布
- OIDC Discovery 元数据端点
- OAuth 授权请求校验（精确 Redirect URI、Scope、State 和 PKCE S256）
- 一次性授权码 Redis 存储和 RS256 Access Token 签发
- OIDC nonce 绑定和 RS256 ID Token 签发
- Refresh Token Redis 存储和轮换
- OIDC UserInfo Bearer Token 校验与按 Scope 返回 Claims
- 管理员 Bearer Token 保护的 Client 创建与列表 API
- Client 更新、启用、禁用和 Secret 轮换 API
- 签名私钥和 `kid` 的本地持久化加载
- HttpOnly Session Cookie、CSRF Cookie 和双提交校验基础
- 用户、登录、Session、授权码和 Client 管理审计事件
- `/oauth/authorize` 和 `/oauth/token` 后端端点初版
- 授权码和 Refresh Token 在绑定、过期和 PKCE 检查通过后使用 Redis 原子消费
- 管理员密钥轮换 API：`POST /api/v1/admin/keys/rotate`，只返回新的 `key_id` 和公开 JWK 数量
- 用户、Client、OAuth/OIDC、Session、JWK 和业务扩展模块边界
- `/auth/login` 辰星通行证浏览器登录页
- `/oauth/authorize/consent` 授权确认页、拒绝回调和 `user_consents` 持久化
- 管理员 bootstrap、登录、注销、HttpOnly Session/CSRF Cookie
- `owner`、`operator`、`auditor` 角色与最小权限矩阵
- 用户列表、用户启停、管理员列表、审计查询和管理后台入口
- `/oauth/revoke` RFC 7009 风格 Token 撤销以及 Discovery 中的撤销端点
- `BusinessExtension` 扩展 trait 与结构化业务 Claim 类型
- 配置驱动的自定义 OAuth/OIDC 提供商管理、加密 Client Secret、外部身份绑定和浏览器回调登录

后续增强方向：

1. 将管理后台入口从轻量服务端 HTML 扩展为完整前端应用。
2. 增加更多真实 OIDC Provider/Client 互操作测试和限流策略。
3. 将签名私钥接入外部受保护密钥存储，并增加密钥撤销策略。
4. 为业务子项目提供经过评审的具体扩展实现。

在对应功能真正实现之前，不应把规划中的接口、环境变量或命令写成已可用能力。

## 本地开发

### 前置条件

- Rust 1.94 或兼容的稳定版工具链
- PostgreSQL 14 或更高版本
- Redis 6 或更高版本

复制 `.env.example` 为 `.env`，按本地环境修改连接地址。服务启动时会自动执行 `migrations/` 中的版本化迁移。

### 常用命令

```powershell
cargo fmt
cargo check --all-targets --all-features
cargo test --all-features
cargo run
```

当前 API：

- `GET /health`：返回服务健康状态
- `POST /api/v1/users`：创建辰星通行证账号，JSON 字段为 `email`、`password` 和可选的 `display_name`
- `POST /api/v1/auth/login`：验证辰星通行证账号并创建 Redis Session，JSON 字段为 `email` 和 `password`
- `GET /auth/login`、`POST /auth/login`：浏览器登录页，仅由带有效授权请求的流程使用
- `GET /oauth/authorize/consent`、`POST /oauth/authorize/consent`：浏览器授权确认和 CSRF 保护
- `DELETE /api/v1/auth/session`：撤销当前 Session，需要 `X-Chenxing-Session` 请求头
- `POST /oauth/token`：授权码/Refresh Token 交换，支持 HTTP Basic 或表单 Client 认证
- `POST /oauth/revoke`：撤销 Access Token 或 Refresh Token
- `GET /oauth/userinfo`：使用 `Authorization: Bearer <access_token>` 返回 OIDC UserInfo
- `POST /api/v1/admin/bootstrap`：仅使用 `ADMIN_TOKEN` 初始化第一个管理员，成功后不可重复 bootstrap
- `POST /api/v1/admin/auth/login`、`DELETE /api/v1/admin/auth/logout`：管理员 API Session
- `GET /api/v1/admin/admins`、`POST /api/v1/admin/admins`：查看/创建管理员；创建操作要求 Owner 和 CSRF
- `GET /api/v1/admin/users`、`POST /api/v1/admin/users/{user_id}/{status}`：用户管理
- `GET /api/v1/admin/audit`：审计查询
- `POST /api/v1/admin/clients`：使用管理员 Bearer Token 注册 Client，Client Secret 只在创建响应中返回
- `GET /api/v1/admin/clients`：使用管理员 Bearer Token 查看 Client 列表
- `PUT /api/v1/admin/clients/{client_id}`：更新 Client 配置
- `POST /api/v1/admin/clients/{client_id}/disable`：禁用 Client
- `POST /api/v1/admin/clients/{client_id}/enable`：启用 Client
- `POST /api/v1/admin/clients/{client_id}/rotate-secret`：轮换 Client Secret
- `POST /api/v1/admin/keys/rotate`：管理员轮换 RS256 签名密钥，旧公钥继续发布
- `GET /api/v1/admin/oauth/providers`、`POST /api/v1/admin/oauth/providers`：查看/创建自定义 OAuth 提供商
- `PUT /api/v1/admin/oauth/providers/{slug}`：更新自定义 OAuth 提供商
- `POST /api/v1/admin/oauth/providers/{slug}/enable`、`/disable`：启停自定义 OAuth 提供商
- `GET /admin/settings/oauth`：可视化配置自定义 OAuth 提供商
- `GET /auth/external/{slug}`、`/callback`：用户通过已启用的外部 OAuth 提供商登录或注册辰星账号

以下能力仍属于后续增强项，当前不应直接视为完整生产认证产品：

- 完整视觉化管理后台 UI（当前提供轻量 HTML 入口和完整管理 API）
- 大规模第三方 OAuth/OIDC 互操作认证矩阵
- 密钥撤销策略和外部受保护密钥存储
- 生产级限流、告警和密钥托管集成

## Docker 部署

服务器安装 Docker Engine、Docker Compose v2 和 `curl` 后，在项目根目录执行：

```bash
./deploy/install.sh
```

脚本首次运行会生成权限为 `0600` 的 `.env`，随机生成 PostgreSQL 密码和 `ADMIN_TOKEN`，先校验生产 Compose 配置，再启动 PostgreSQL、Redis 和认证服务，并等待 `/health` 返回成功。已有 `.env` 不会被覆盖；生产环境应将 `APP_ISSUER` 设置为固定的 HTTPS 地址，并将 `.env` 作为秘密文件保护。健康检查失败时脚本会输出 Compose 状态和应用日志，便于定位启动问题。

生产 Compose 文件为 `docker-compose.prod.yml`。数据库、Redis 和 JWK 密钥分别使用 Docker volume 持久化，应用容器以非 root 用户运行。默认只发布认证 API 端口，TLS 和反向代理应由服务器网关提供。

## GitHub Actions

- `.github/workflows/ci.yml`：Rust 1.94 格式化、编译、测试、Clippy 和 `cargo-llvm-cov` 覆盖率门槛（行覆盖率至少 75%）。
- `.github/workflows/build.yml`：构建 Linux x86_64/ARM64、Windows GNU/MSVC、macOS x86_64/ARM64 二进制；打 `v*` tag 时生成 `.tar.gz`/`.zip` 发布包、`SHA256SUMS` 并创建 GitHub Release，同时构建发布 Linux `amd64/arm64` 的 GHCR 镜像。

GitHub Actions 使用 MIT 项目可用的公开仓库免费额度；发布镜像需要仓库 Actions 具备 `packages: write` 权限。

当前 `/oauth/authorize` 同时支持开发期 `X-Chenxing-Session` 和 HttpOnly Session Cookie；带 `Accept: text/html` 的浏览器流程会进入登录页和授权确认页。浏览器 Cookie 会话的状态变更必须携带 `X-CSRF-Token`，并与 CSRF Cookie 和 Session 中的 Token 一致。管理员 Session 使用独立 Cookie 名称和相同的双提交 CSRF 约束。

`KEY_DIRECTORY` 默认指向 `data/keys`，该目录包含运行时私钥并已加入 `.gitignore`。`ADMIN_TOKEN` 为空时，管理 API 默认全部拒绝访问。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。除非另有明确说明，项目中的源代码和文档均按该许可证发布。
