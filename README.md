# 天穹辰星 · 辰星认证中枢

<div align="center">
<img style="width:70%" src="https://count.getloli.com/@chenxing-auth?name=chenxing-auth&theme=booru-lewd&padding=6&offset=0&align=top&scale=1&pixelated=1&darkmode=auto" alt="chenxing-auth visit count">
</div>

辰星认证中枢是独立运行的登录认证平台，面向天穹辰星各子项目平台及其他受信任应用提供统一身份认证能力。它在产品、服务和数据边界上独立于天穹辰星的其他业务平台，不承载具体子项目的业务功能。

用户侧产品名称为 **辰星通行证**。用户创建辰星通行证账号后，可以使用该账号注册和登录天穹辰星的其他子项目平台。平台提供统一登录、OAuth 2.0 / OpenID Connect（OIDC）授权、用户与 Client 管理、会话管理，以及隔离的业务扩展接口。

当前仓库包含可运行的后端和同源 React Web 控制台。浏览器登录、注册、资料与 Session 管理、用户 OAuth Client 管理、OAuth/OIDC 授权码流程和 Docker/GitHub Actions 已实现；前端构建产物会内嵌进 Rust 二进制，由同一个 Axum 服务提供，不要求单独的静态站点或反向代理。

## 项目定位

- **品牌**：天穹辰星
- **平台**：辰星认证中枢
- **用户产品**：辰星通行证
- **全称**：天穹辰星 · 辰星认证中枢
- **许可证**：MIT License

平台的核心目标是让各子项目和外部应用通过标准协议接入独立的统一身份体系：用户只需维护一套辰星通行证账号，即可在不同接入平台间使用；各接入平台仍独立维护自己的业务资料、权限和业务数据。认证平台自身只负责身份、认证、授权和相关安全能力，不直接管理子项目业务。

## 功能概览

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
- 邮件变更验证码与安全告警通过 PostgreSQL outbox 异步投递；SMTP 外部副作用采用 at-least-once（至少一次）语义，极少数故障恢复时可能重复发送

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

## 开发状态与路线图

浏览器登录注册、TOTP / WebAuthn 因子、OAuth 2.0 / OIDC 授权码流程（PKCE、Refresh Token 轮换、Token 撤销）、JWK 密钥轮换、用户与 Client 管理控制台、角色权限、审计和自定义外部 OAuth 提供商接入均已实现。

自定义外部提供商当前按 OAuth 2.0 授权码 + UserInfo 信任模型接入（`trust_model: "oauth2_userinfo"`）；本平台作为 OP 对下游 Client 完整支持 OIDC，但在上游这一侧不是 OIDC 依赖方，不解析上游 `id_token`。

后续增强方向：

1. 将管理后台入口从轻量服务端 HTML 扩展为完整前端应用。
2. 增加更多真实 OIDC Provider/Client 互操作测试和限流策略。
3. 将签名私钥接入外部受保护密钥存储，并增加密钥撤销策略。
4. 为业务子项目提供经过评审的具体扩展实现。
5. 为自定义外部提供商增加 OIDC 依赖方模式：固定 issuer/JWKS/允许算法与 nonce 策略，验证 ID Token 签名、`kid`、`iss`、`aud`、`exp`、`iat` 与 nonce，并校验 UserInfo `sub` 与已验证 ID Token 一致。在该模式落地前，产品与 API 只声明 OAuth 2.0 + UserInfo。

以下能力仍属于后续增强项，当前不应直接视为完整生产认证产品：

- 大规模第三方 OAuth/OIDC 互操作认证矩阵
- 自定义外部提供商的 OIDC 依赖方模式（ID Token 签名与 `iss`/`aud`/`exp`/`nonce` 验证）；当前只提供 OAuth 2.0 + UserInfo 信任模型
- 密钥撤销策略和外部受保护密钥存储
- 生产级限流、告警和密钥托管集成

## 快速开始

### 前置条件

- Rust 1.94 或兼容的稳定版工具链
- Node.js 22 或兼容版本及 npm
- PostgreSQL 14 或更高版本
- Redis 6 或更高版本

### 配置

复制 `.env.example` 为 `.env`，按本地环境修改数据库和 Redis 连接地址。两点注意：

- 本地 HTTP 开发时显式设置 `COOKIE_SECURE=false`；HTTPS 或非 loopback 环境必须保持 `COOKIE_SECURE=true`。
- 新环境不要在 `.env` 中写 `APP_ISSUER`：先完成迁移和首个 Owner 初始化，再由 Owner 在管理设置中写入固定 Issuer。

数据库迁移通过 `cargo run -- migrate` 手动执行，正常服务启动不会修改数据库结构。连接池、限流、审计归档等运行时配置项的完整说明见 `.env.example`。

### 开发脚本

项目根目录提供三份开发脚本：

- `./dev.sh` — 一键启动完整开发环境（Docker 基础设施 + 前后端），`Ctrl+C` 只停止前后端，Docker 容器保持运行
- `./dev-docker.sh` — 仅启动 PostgreSQL 和 Redis（分离模式），脚本退出后容器继续运行
- `./dev-services.sh` — 仅启动前后端（需要先启动 Docker 基础设施），`Ctrl+C` 停止前后端

日常开发推荐工作流：每日首次启动运行 `./dev.sh`，后续代码修改后只需 `Ctrl+C` 停止前后端再重新运行 `./dev-services.sh`，无需反复重启数据库容器。停止 Docker 服务使用 `docker compose down`。

`cargo build`/`cargo run` 在缺少 `web/dist/index.html` 时会通过 Cargo build script 自动安装并构建 Web。启动后访问 `http://127.0.0.1:3000/` 即可同时使用 Web 和 API。

## Docker 部署

安装必须是一键的。在一台已安装 Docker Engine 和 Docker Compose v2 的服务器上，
粘贴两行命令即可完成部署：

```bash
mkdir -p /opt/chenxing-auth && cd /opt/chenxing-auth
wget -O manage.sh https://raw.githubusercontent.com/chenming0v0/chenxing-auth/releases/manage.sh && bash ./manage.sh
```

脚本会自动解析最新发布版本、生成全部随机密钥（保存在部署目录 `.env`，权限 0600）、
拉取镜像、执行数据库迁移并启动服务，最后等待健康检查通过。交互时只会问一个对外端口；
无人值守安装用 `CHENXING_PORT=8080` 覆盖即可。

**升级：在部署目录重新运行同一条命令。**

```bash
bash ./manage.sh
```

`manage.sh` 检测到已有 `.env` 时自动走升级：先执行数据库迁移，成功后才切换新版本，
`.env` 中的密钥和配置原样保留。迁移或就绪检查失败时旧版本保持运行。禁止手动
`docker compose pull && up -d`，那会绕过数据库迁移。

固定版本或回滚时才需要显式指定版本：

```bash
CHENXING_RELEASE_VERSION=v1.1.20 bash ./manage.sh
```

排查问题时可以加 `--debug` 参数输出诊断信息。v1.1.26 之前的旧部署升级前请重新
执行上面的 `wget` 一次性刷新 `manage.sh`（旧安装器依赖已停止发布的 Release 清单资产）。

首次部署完成后，打开站点会引导创建首个所有者账号。刚登录时无法注册新用户；在管理设置里配置好本站的 Issuer（站点的固定 HTTPS 地址）后，注册和 OAuth 登录能力才会开放。

### 源码构建部署

服务器安装 Docker Engine、Docker Compose v2 和 `curl` 后，在项目根目录执行：

```bash
./deploy/install.sh
```

脚本首次运行会自动生成配置和随机凭据，启动 PostgreSQL、Redis 和认证服务并等待健康检查通过；已有配置不会被覆盖，已有数据库会自动原地升级并保留业务数据。

生产 Compose 文件为 `docker-compose.prod.yml`。数据库、Redis、JWK 密钥和内嵌 Web 都由应用容器提供，应用容器以非 root 用户运行。TLS 终止可以交给服务器网关，但 Web/API 本身不依赖反向代理。

## API 文档

- [给人看的 API 文档](https://wiki.auth.clya.top)
- [给 AI 看的 API 文档](https://wiki.auth.clya.top/llms.txt)

可导入的 OpenAPI 契约文件为仓库根目录的 [`openapi.yaml`](openapi.yaml)。

## 更多文档

- [Email Outbox Worker 健康与监控](docs/email-worker-health.md)
- [GitHub Actions 供应链固定策略](docs/github-actions-supply-chain.md)

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。除非另有明确说明，项目中的源代码和文档均按该许可证发布。
