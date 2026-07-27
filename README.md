# 天穹辰星 · 辰星认证中枢

辰星认证中枢是独立运行的登录认证平台，面向天穹辰星各子项目平台及其他受信任应用提供统一身份认证能力。它在产品、服务和数据边界上独立于天穹辰星的其他业务平台，不承载具体子项目的业务功能。

用户侧产品名称为 **辰星通行证**。用户创建辰星通行证账号后，可以使用该账号注册和登录天穹辰星的其他子项目平台。平台计划提供统一登录、OAuth 2.0 / OpenID Connect（OIDC）授权、用户与 Client 管理、会话管理，以及面向业务系统的认证扩展能力。

> 当前项目处于后端初始化和协议能力建设阶段。核心用户、Session、Client、OAuth/OIDC 授权码、PKCE、Access Token、OIDC ID Token、UserInfo、JWKS、Refresh Token 和审计能力已建立；登录页、授权确认页、完整管理后台和生产级互操作仍在开发中。

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

建议的代码边界如下，实际目录会以实现阶段的设计为准：

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
- 签名密钥支持轮换，JWKS 发布必须保留必要的旧公钥以完成令牌验证过渡。
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
- 用户、Client、OAuth/OIDC、Session、JWK 和业务扩展模块边界

后续按以下顺序推进：

1. 完成登录页面、授权确认页面和完整浏览器 Cookie/CSRF 流程。
2. 完成完整管理后台、管理员身份体系和权限分级。
3. 增加密钥多版本轮换、旧公钥保留和受保护密钥存储。
4. 增加完整 OAuth/OIDC 互操作测试和业务扩展接口。
5. 增加部署、安全测试、限流和生产可观测性。

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
- `DELETE /api/v1/auth/session`：撤销当前 Session，需要 `X-Chenxing-Session` 请求头
- `GET /oauth/userinfo`：使用 `Authorization: Bearer <access_token>` 返回 OIDC UserInfo
- `POST /api/v1/admin/clients`：使用管理员 Bearer Token 注册 Client，Client Secret 只在创建响应中返回
- `GET /api/v1/admin/clients`：使用管理员 Bearer Token 查看 Client 列表
- `PUT /api/v1/admin/clients/{client_id}`：更新 Client 配置
- `POST /api/v1/admin/clients/{client_id}/disable`：禁用 Client
- `POST /api/v1/admin/clients/{client_id}/enable`：启用 Client
- `POST /api/v1/admin/clients/{client_id}/rotate-secret`：轮换 Client Secret

以下能力仍在开发中，尚不可作为完整生产能力使用：

- 登录和授权确认页面
- 完整管理后台 UI 和管理员身份体系
- 授权码/Token 的完整 OAuth/OIDC 互操作测试
- 完整的 OIDC 登录交互、授权确认页面和 nonce 验证端到端测试
- 多版本密钥轮换、撤销策略和受保护密钥存储
- Docker 或其他部署方式的生产配置

当前 `/oauth/authorize` 同时支持开发期 `X-Chenxing-Session` 和 HttpOnly Session Cookie；浏览器 Cookie 会话的状态变更必须携带 `X-CSRF-Token`，并与 CSRF Cookie 和 Session 中的 Token 一致。完整登录页和授权确认页面仍未实现。

`KEY_DIRECTORY` 默认指向 `data/keys`，该目录包含运行时私钥并已加入 `.gitignore`。`ADMIN_TOKEN` 为空时，管理 API 默认全部拒绝访问。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。除非另有明确说明，项目中的源代码和文档均按该许可证发布。
