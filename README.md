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

## 当前开发状态

当前已完成：

- Axum 服务入口和 `/health` 健康检查
- 环境配置加载与启动校验
- PostgreSQL 连接池边界、请求路径语句超时和初始迁移
- Redis Client 边界
- 用户注册输入校验和 Argon2 密码哈希
- `POST /api/v1/users` 基础注册接口
- `POST /api/v1/auth/login` 密码登录并执行 TOTP 或 WebAuthn 因子流程
- RSA 2048 位签名密钥生成和 JWKS 发布
- OIDC Discovery 元数据端点
- OAuth 授权请求校验（精确 Redirect URI、Scope、State 和 PKCE S256）
- 一次性授权码 Redis 存储和 RS256 Access Token 签发
- OIDC nonce 绑定和 RS256 ID Token 签发
- Refresh Token Redis 存储和轮换
- OIDC UserInfo Bearer Token 校验与按 Scope 返回 Claims
- 管理员 Bearer Token 或普通 Session 保护的 Client 创建与列表 API（浏览器写操作需要 `X-CSRF-Token`）
- Client 更新、启用、禁用和 Secret 轮换 API
- 签名私钥和 `kid` 的本地持久化加载
- HttpOnly Session Cookie、CSRF Cookie 和双提交校验基础
- 用户、登录、Session、授权码和 Client 管理审计事件
- `/oauth/authorize` 和 `/oauth/token` 后端端点初版
- 授权码和 Refresh Token 在绑定、过期和 PKCE 检查通过后使用 Redis 原子消费
- 管理员密钥轮换 API：`POST /api/v1/admin/keys/rotate`，只返回新的 `key_id` 和公开 JWK 数量
- 用户、Client、OAuth/OIDC、Session、JWK 和业务扩展模块边界
- `/login` 辰星通行证 React 浏览器登录页，登录请求使用 `POST /api/v1/auth/login`
- `/oauth/consent` React 授权确认页、拒绝回调和 `user_consents` 持久化
- Owner bootstrap、统一用户登录、注销、HttpOnly Session/CSRF Cookie
- 统一用户管理 Web 控制台与 PostgreSQL 持久化的注册邮件发件地址设置
- `user`、`admin`、`owner` 层级角色与最小权限矩阵
- 用户列表、用户启停、角色管理、特权用户列表、审计查询和管理后台入口
- `/oauth/revoke` RFC 7009 风格 Token 撤销以及 Discovery 中的撤销端点
- `BusinessExtension` 扩展 trait 与结构化业务 Claim 类型
- 配置驱动的自定义 OAuth 2.0 提供商管理、加密 Client Secret、外部身份绑定和浏览器回调登录

自定义外部提供商按 **OAuth 2.0 授权码流程 + UserInfo** 信任模型接入：身份字段只来自用 access token 经 TLS 取回的 UserInfo 响应，令牌响应中的 `id_token` 不被解析也不参与身份判定。本平台**作为 OP 对下游 Client 完整支持 OIDC**，但在上游自定义提供商这一侧**不是 OIDC 依赖方**，不保存 issuer/JWKS/算法策略，也不执行 ID Token 签名与 `iss`/`aud`/`exp`/`nonce` 校验。管理 API 用 `trust_model: "oauth2_userinfo"` 显式声明这一边界。

后续增强方向：

1. 将管理后台入口从轻量服务端 HTML 扩展为完整前端应用。
2. 增加更多真实 OIDC Provider/Client 互操作测试和限流策略。
3. 将签名私钥接入外部受保护密钥存储，并增加密钥撤销策略。
4. 为业务子项目提供经过评审的具体扩展实现。
5. 为自定义外部提供商增加 OIDC 依赖方模式：固定 issuer/JWKS/允许算法与 nonce 策略，验证 ID Token 签名、`kid`、`iss`、`aud`、`exp`、`iat` 与 nonce，并校验 UserInfo `sub` 与已验证 ID Token 一致。在该模式落地前，产品与 API 只声明 OAuth 2.0 + UserInfo。

## 本地开发

### 前置条件

- Rust 1.94 或兼容的稳定版工具链
- Node.js 22 或兼容版本及 npm
- PostgreSQL 14 或更高版本
- Redis 6 或更高版本

复制 `.env.example` 为 `.env`，按本地环境修改连接地址。新环境不要把 `APP_ISSUER` 写入 `.env`：先完成数据库迁移和首个 Owner 初始化，再由 Owner 在管理设置中写入固定 Issuer，服务会从 PostgreSQL `app_settings` 热加载。使用 HTTP 本地开发时将 `COOKIE_SECURE` 显式设为 `false`；HTTPS 或非 loopback 环境必须保持 `COOKIE_SECURE=true`。旧开发环境保留的 `APP_ISSUER` 只作为兼容导入，不得从请求 Host 推导。正常服务启动不会修改数据库结构；需要执行迁移时运行 `cargo run -- migrate`，生产 Docker 部署脚本会在启动应用前显式执行同一迁移命令。审计归档不在 Web 服务启动时自动运行，只有单独的 `cargo run -- audit-archive` 维护命令会搬运过期热表事件。

数据库连接分成两个用途不同的池。请求路径使用的应用池会在每条新连接上设置服务端 `statement_timeout`，默认 `DB_STATEMENT_TIMEOUT_MS=5000`（允许 100 至 60000 毫秒）：`REQUEST_TIMEOUT_SECONDS` 只放弃 HTTP 响应，PostgreSQL 后端仍在执行，连接不会归还，因此语句上限必须由数据库自己执行，否则少量卡住的查询就能抽干连接池并让登录和令牌签发一起失败。该变量取值越界或不是整数时直接启动失败，不静默回退，避免运维以为自己配置的上限生效；设为 `0` 表示显式关闭（仅在数据库角色已带 `ALTER ROLE ... SET statement_timeout` 时使用），启动时会记录警告。`migrate` 和 `audit-archive` 走独立的维护池，不带 `statement_timeout`，长时间 DDL 和归档批次不会被中途取消。

进程收到 SIGTERM 或关键 worker 失败后，会同时通知 HTTP 服务和后台 worker 开始退出。HTTP 连接的 graceful drain 受 `HTTP_GRACEFUL_DRAIN_SECONDS` 约束（默认 15 秒，必须大于 0）：请求超时层不覆盖静态 SPA/asset 响应，也不限制慢客户端消费响应体的时间，因此必须另有总截止时间。截止后进程会中止剩余连接并记录可诊断警告。Worker drain 仍是 10 秒上限，与 HTTP drain 并行，不再被无界的 `server.await` 挡住。

#### 快速启动

项目根目录提供三份开发脚本：

- `./dev.sh` — 一键启动完整开发环境（Docker 基础设施 + 前后端），`Ctrl+C` 只停止前后端，Docker 容器保持运行
- `./dev-docker.sh` — 仅启动 PostgreSQL 和 Redis（分离模式），脚本退出后容器继续运行
- `./dev-services.sh` — 仅启动前后端（需要先启动 Docker 基础设施），`Ctrl+C` 停止前后端

日常开发推荐工作流：每日首次启动运行 `./dev.sh`，后续代码修改后只需 `Ctrl+C` 停止前后端再重新运行 `./dev-services.sh`，无需反复重启数据库容器。停止 Docker 服务使用 `docker compose down`。

认证失败限流由 Redis Lua 脚本在单次原子操作中完成计数、窗口 TTL 和阈值判定。生产默认使用 `AUTH_LIMITER_FAILURE_POLICY=fail-closed`：Redis 不可用时认证请求不会被放行，并记录结构化 `auth_limiter.redis_unavailable` 事件；只有在明确接受降级风险时才使用 `fail-open`。

`AUTH_LIMITER_MISSING_SOURCE_IP=reject` 是生产默认值，防止没有可信 `ConnectInfo` 的请求共用全局 `unknown` 桶；`skip` 只跳过 IP 维度，仍保留 account、ticket 限流，并应仅用于明确配置的测试或受控入口。限流日志只记录维度、窗口和不可逆 key hash，不记录账户、ticket、IP 原文或认证凭据。

限流阈值来自 `app_settings.security_limits`，但认证热路径不逐次查询数据库：`SettingsService` 在进程内缓存一份已校验的阈值，TTL 5 秒，管理接口写入成功后主动刷新本实例缓存，多实例部署由 TTL 收敛。阈值读取失败时使用最后一次成功加载的值，从未成功加载过则使用启动期环境变量默认值，并按同一个 `AUTH_LIMITER_FAILURE_POLICY` 处置：`fail-open` 带着该降级阈值继续限流（阈值仍然生效，认证不返回 500），`fail-closed` 明确拒绝认证。两种情况都记录结构化 `auth_limiter.settings_unavailable` 事件，字段包含 `policy`、`limits_source` 和 `operation`；读取失败后有 1 秒重试退避，故障期间不会每个认证请求都再打一次数据库。`clear` 与 `release` 不读取阈值，因此成功认证后的计数清理与在途配额归还不受 settings 故障影响。

#### Redis 凭据状态与崩溃恢复

授权码消费、Refresh Token rotation 的前驱删除/后继写入、`Consumed` tombstone、显式撤销和 family 撤销标记都是 Redis 的权威安全状态，不能按普通缓存恢复。生产 Compose 与安装器使用命名卷 `/data`、AOF、`appendfsync always`，并在 AOF 截断时拒绝启动；同一卷真实兑现 fsync 时，已确认成功的凭据变更目标为 **RPO 0**。代价是同步存储延迟和 IOPS 上升，恢复 `everysec` 会重新引入约一秒的凭据复活窗口。

卷丢失或只有陈旧备份时不得直接恢复并接流量：备份点之后的消费、rotation、tombstone 和 revoke 会被回滚。安全默认是使用空 Redis，让短期凭据全部失效并要求重新登录/授权；详细的权威状态、备份边界、性能代价和故障后验证步骤见 [`docs/redis-durability.md`](docs/redis-durability.md)。

数据库使用 forward-only 的 SQLx 迁移链。`migrations/0001_initial.sql` 至 `0027_repair_canonical_email_constraint_scope.sql` 是已经发布的历史，文件名和 SQL 字节永久冻结；后续结构变化只能使用新的递增版本号追加。当前的 Issuer 持久化与套餐配额上界分别位于 `0028`、`0029`。`src/db/mod.rs` 显式嵌入完整迁移链，因此旧部署保留的 `_sqlx_migrations` 记录会先校验原 checksum，再从最后成功版本继续升级。

升级前仍应按生产变更流程备份 PostgreSQL，但正常升级不需要也不应清库、删除 volume 或手工改写 `_sqlx_migrations`。`migrations/published-checksums.sha256` 固定所有已发布迁移，`migrations/checksums.sha256` 覆盖当前完整链，CI 同时验证文件字节、已发布前缀和文件清单。v1.1.1 与 v1.1.2 曾发布过压平后的迁移 ledger；升级器只在 checksum 序列精确匹配这些已知发布、且关键表、列、索引、约束、函数和触发器均符合对应版本时，才在 SQLx 的迁移锁内原子修复 ledger 并继续升级。其他 checksum 不匹配或 schema 漂移一律停止部署，必须先确认数据库来源和损坏情况，不能用手工 UPDATE 绕过校验。

审计事件由 `audit_events` 和 `audit_events_archive` 两张表保存。迁移创建的数据库触发器拒绝两张表的 `UPDATE`、`DELETE` 和 `TRUNCATE`；migration/owner role 与 `chenxing_runtime` 分离后，runtime role 对两张审计表没有任何修改权限，归档只通过固定 `search_path` 的最小权限 `SECURITY DEFINER` 函数完成。触发器保留为纵深防御，不再作为唯一边界。归档先复制后删除，且只删除已成功复制的行；归档表本身永久保留并拒绝修改。审计查询会合并两张表。

角色分离必须真的配置出来才成立：PostgreSQL 里表 owner 隐含全部表权限，因此当 `MIGRATION_DATABASE_URL` 缺失、迁移与运行时共用同一角色时，基线里的 `REVOKE` 一行都不生效，审计 append-only 退回只剩触发器一层，而触发器的归档旁路标记是会话级 GUC，任何持有该角色的会话都能设置。`cargo run -- migrate` 因此在连库前先校验角色配置，迁移后再用 `has_table_privilege` 实测运行时角色此刻能不能 `UPDATE`/`DELETE`/`TRUNCATE` 审计表——这个函数把 owner 隐含权限、角色继承和 superuser 旁路都算在内，问的是实际权限而不是迁移文件写了什么。默认策略 `AUDIT_ROLE_SEPARATION=require` 下不满足即拒绝；只有显式设置 `AUDIT_ROLE_SEPARATION=allow-single-role` 才允许单角色部署，且每次 migrate 都会打出强告警。生产环境不得使用该开关。

运行时角色对序列的权限只放开一个对象：`users.id` 的 identity 序列。Owner 初始化要求第一个 Owner 的 `id` 为 1，`bootstrap_owner` 因此在插入前调 `setval`，而 `setval` 在 PostgreSQL 里要求序列的 `UPDATE` 权限；完整基线只授这一个序列。审计表的序列保持只读，append-only 边界不受影响。

运行时角色口令由 migrate 保证可用，但不会被无条件重写：migrate 先用 `DATABASE_URL` 真正登录一次，口令已经可用就完全不碰角色；只有服务端返回 SQLSTATE `28P01`（invalid_password）或角色刚被创建才写入并记录告警。`28000` 及其他 28 类授权错误（HBA、身份映射等）会 fail-safe 中止口令管理，绝不执行 `ALTER ROLE`。口令完全由外部密钥托管管理时设置 `MIGRATION_MANAGE_RUNTIME_PASSWORD=false`，migrate 便不再执行任何 `ALTER ROLE ... PASSWORD`。

`AUDIT_ARCHIVE_ENABLED` 默认是 `false`。明确设置为 `true` 后，`AUDIT_RETENTION_DAYS`（默认 2555 天，允许 1 至 36500 天）定义事件留在热表的最短时间；超过该窗口的事件只是被搬到永久归档表，不会被物理丢弃。Web 请求和正常服务进程不会执行清理，部署必须由一个外部 cron/systemd 任务定期运行 `cargo run -- audit-archive`（Docker 部署使用 `docker compose --env-file .env -f docker-compose.prod.yml run --rm app audit-archive`）。每次命令最多处理 1000 行，重复调用安全；命令日志只记录批次数和保留窗口，不记录 action、resource、metadata 或其他事件内容。不要让多个部署副本各自建立定时器，也不要在未确认合规窗口前缩短保留天数。回滚迁移前先停用调度器，并按迁移注释把归档行恢复到热表，再按逆序删除对象。

`cargo build`/`cargo run` 在缺少 `web/dist/index.html` 时会通过 Cargo build script 自动安装并构建 Web。GitHub Actions 发布流水线会先构建一次前端产物，再在各目标平台复用；推送到 GHCR 的多架构镜像只打包已经编好的 Linux 二进制，不再在容器里二次 `cargo build`。本地 `docker compose` 仍使用源码版 `Dockerfile` 现场编译。启动后访问 `http://127.0.0.1:3000/` 即可同时使用 Web 和 API。

二进制只在编译期内嵌 `index.html` 这一个 SPA shell，它引用的 JS、CSS、favicon 和字体仍然按文件从磁盘提供。因此两条生产镜像路径都会把构建好的 `web/dist` 一起装进镜像的 `/usr/local/share/chenxing-auth/web/dist`，并把 `WEB_DIST_DIR` 指向该目录：镜像的 WORKDIR 是可变状态目录，相对路径 `web/dist` 找不到产物，页面会只剩空壳。GHCR 镜像和原生 release tar/zip 都装入编译这批二进制时用的同一份 `web-dist` artifact；原生归档把二进制放在根目录、完整前端放在 `web/dist`，解压到空目录后即可直接启动，无需另行下载或拼配前端文件。

`WEB_DIST_DIR` 在启动期解析完毕，不存在请求期回退：路径先 `canonicalize`（消掉 `..` 与符号链接），再逐条校验。留空、目录不存在、指向普通文件、指向文件系统根、等于或包含进程工作目录、与 `KEY_DIRECTORY` 有任何重叠（相等、包含、被包含），以及顶层出现源码/状态目录（`src`、`migrations`、`Cargo.toml`、`.git`、`target`、`node_modules`、`data`、`keys`）或秘密材料（`.env*`、`*.pem`、`*.key`、`*.der`、`*.kid` 等）时，服务直接以一条明确的配置错误拒绝启动，而不是把工作目录整体当静态根把 `.env` 和私钥暴露成可下载文件。目录还必须自证与本二进制同源：`index.html` 在盘上，且内嵌 shell 引用的每个根绝对资源都能在同一个根下找到——挂进另一次构建的产物会在启动时被拒绝，而不是等到每个资源 404 才被发现。`migrate` 与 `audit-archive` 子命令不托管静态资源，不受这条校验影响。

## API 文档

- [给人看的 API 文档](https://wiki.auth.clya.top)
- [给 AI 看的 API 文档](https://wiki.auth.clya.top/llms.txt)


以下能力仍属于后续增强项，当前不应直接视为完整生产认证产品：

- 用户已授权应用的聚合列表 API（当前页面明确展示后端能力边界）
- 大规模第三方 OAuth/OIDC 互操作认证矩阵
- 自定义外部提供商的 OIDC 依赖方模式（ID Token 签名与 `iss`/`aud`/`exp`/`nonce` 验证）；当前只提供 OAuth 2.0 + UserInfo 信任模型
- 密钥撤销策略和外部受保护密钥存储
- 生产级限流、告警和密钥托管集成

## Docker 部署

推荐在一台已经安装 Docker Engine 和 Docker Compose v2 的服务器上直接下载安装器：

```bash
wget -O install.sh https://raw.githubusercontent.com/chenming0v0/chenxing-auth/releases/install.sh
bash install.sh
```

安装器会生成独立部署目录和权限为 `0600` 的 `.env`，并依次拉取辰星认证中枢、
PostgreSQL 和 Redis 镜像。三个 `docker pull` 的分层下载与解压进度不会隐藏；随后会
显示数据库迁移、容器启动和就绪检查过程。安装器只以应用容器内的 `GET /health/ready` 返回 200 为准；该端点同时确认数据库、Redis、四个关键后台 worker 和签名密钥同步均就绪，只有 liveness 成功而依赖尚未就绪时不会误报成功。若就绪端点持续失败，超时诊断会输出 Compose 服务状态、应用容器 health 状态和应用日志。默认使用
`ghcr.io/chenming0v0/chenxing-auth:latest`，可通过 `CHENXING_IMAGE` 覆盖。

新实例不要求安装时已经拥有域名，安装器生成的 `.env` 也不包含 `APP_ISSUER`。数据库
尚未写入 Issuer 时，进程进入保护模式：`/health*` 健康检查、静态前端和首个 Owner
初始化保持可用；ID=1 的首 Owner 可以本地登录，`ADMIN_TOKEN` 是管理 API 的恢复通道。
公开注册、普通用户创建、管理员/Owner 创建关闭；只有依赖正式 Issuer 的 OAuth/OIDC、
Discovery、JWKS 和外部登录路由关闭。该模式不是把全部认证或管理 API 返回 503。

先通过 `POST /api/v1/admin/bootstrap` 初始化首个 Owner，再登录管理控制台，在 Issuer
设置中写入固定的 HTTPS URL。该值保存到 PostgreSQL `app_settings`，当前进程立即热更新，
其他实例按 generation 收敛；不能从请求 Host 或反向代理输入推导。旧部署若仍在 `.env`
中保留 `APP_ISSUER`，运行时只会在数据库没有 Issuer 时按兼容规则导入一次，数据库设置优先。

Issuer 第一次写入后允许用相同值幂等重试；不同值会被拒绝，避免静默作废现有令牌、
Cookie 和 Passkey 绑定。

### 源码构建部署

服务器安装 Docker Engine、Docker Compose v2 和 `curl` 后，在项目根目录执行：

```bash
./deploy/install.sh
```

该源码部署脚本首次运行会生成权限为 `0600` 的 `.env`，随机生成 PostgreSQL 密码、runtime 数据库密码和 `ADMIN_TOKEN`，不生成 `APP_ISSUER`；它会先校验生产 Compose 配置，再启动 PostgreSQL、Redis 和认证服务，并等待 `/health` 返回成功。没有 Issuer 时脚本仍会完成部署，服务进入上面的保护模式。已有 `.env` 不会被覆盖，但缺少 runtime 角色凭据时会自动追加；旧 `.env` 中的 `APP_ISSUER` 仍按兼容规则读取。已有数据库会按冻结的历史迁移 checksum 原地继续升级并保留业务数据；健康检查失败时脚本会输出 Compose 状态和应用日志，便于定位启动问题。

生产 Compose 文件为 `docker-compose.prod.yml`。数据库、Redis、JWK 密钥和内嵌 Web 都由应用容器提供，应用容器以非 root 用户运行。TLS 终止可以交给服务器网关，但 Web/API 本身不依赖反向代理。

## GitHub Actions

当前 `/oauth/authorize` 同时支持开发期 `X-Chenxing-Session` 和 HttpOnly Session Cookie；带 `Accept: text/html` 的浏览器流程会进入登录页和授权确认页。浏览器 Cookie 会话的状态变更必须携带 `X-CSRF-Token`，并与 CSRF Cookie 和 Session 中的 Token 一致。管理 API 复用普通用户 Session 和 CSRF Cookie，角色决定管理权限。

`KEY_DIRECTORY` 默认指向 `data/keys`，该目录包含运行时私钥并已加入 `.gitignore`。Unix 下应用会将目录收紧为 `0700`，并校验目录及必要祖先的 owner 有效 uid 与写权限边界：叶子必须属于当前有效用户且不含 group/other 位，祖先必须属于本进程或 root，且不可被他人改写（root+sticky 如 `/tmp` 除外）。私钥、active `kid` 和 OAuth Provider 主密钥收紧为 `0600`。关键文件操作绑定目录 fd，经 `openat2`/`openat` 拒绝符号链接，打开后 `fstat` 同一 inode，避免路径级 check-then-open。Windows 上等价边界是受保护 DACL 与不跟随重解析点的句柄打开：叶子目录和密钥文件只允许当前进程/服务帐户与 `NT AUTHORITY\\SYSTEM`，已有宽松或外来主体的 ACL 直接拒绝而不会静默改写；符号链接、junction 与其它重解析点一律 fail-closed。其它非 Unix/非 Windows 目标没有这套原语，安全文件操作返回 `Unsupported`。部署要求见 `docs/security/key-storage.md`。密钥写入使用受限临时文件和原子替换；签名密钥与 Provider Secret 使用互不重叠的 `.chenxing-key-` / `.chenxing-secret-` 前缀，各自只清理本命名空间。active `kid` 存在但它指向的私钥材料不在目录里时，服务 fail-closed：启动和刷新直接失败并记录一条不含密钥材料的 error 日志，既不覆盖 `kid` 也不生成替代密钥，避免静默作废全部已签发令牌并抹掉材料丢失的证据；只有目录既没有 `kid` 也没有任何私钥材料时才执行首次初始化。恢复方式是还原备份的私钥文件，或在确认可以接受全部已签发令牌失效后手动清空密钥目录。Provider/SMTP 加密主密钥 `oauth-provider-secret.key` 另有数据库恢复保护：启动会先检查 `oauth_providers.client_secret_ciphertext` 与 SMTP 设置中的非空 `password_ciphertext`；只要存在任何存量密文，主密钥文件缺失就会明确拒绝启动且不会生成替代钥匙，必须还原原文件后再启动。只有数据库没有任何这类密文时才视为首次初始化并生成主密钥；数据库状态无法读取或 SMTP JSON 无法解析时同样 fail-closed。`KEY_ROTATION_GRACE_SECONDS` 默认是 `604800`（7 天），支持范围是 `1` 到 `2592000` 秒（30 天），且不能小于 access/ID token TTL：轮换后的旧公钥在该窗口内继续用于验签，窗口外的旧私钥会在启动或后续轮换时回收；设置为 `0` 或超出范围会使服务启动失败。`KEY_ROTATION_SKEW_ALLOWANCE_SECONDS` 默认是 `3600`（1 小时），支持范围是 `0` 到 `KEY_ROTATION_GRACE_SECONDS`：多实例共享密钥目录时，`retired_at` 由退役实例的时钟写入、窗口判断却发生在当前加载实例的时钟上，时钟偏快的实例会把窗口算短、提前删除仍被其他实例用于验签的公钥文件（不可逆）；该容忍值把窗口关闭边界推到 `retired_at + grace + allowance`，偏差不超过容忍值的实例只会晚删、绝不提前删，单实例部署可设为 `0`。签发、验签和 JWKS 三条请求热路径只读进程内的密钥快照，不在请求线程里读写密钥目录；与共享 `KEY_DIRECTORY` 的一致性由一个 5 秒周期的后台任务负责（验签遇到未知 `kid` 时会提前触发一次同步）。密钥轮换先把新公钥写入 JWKS（`published`），再等到 `KEY_ACTIVATION_DELAY_SECONDS`（默认 65，覆盖 JWKS `max-age=60` 与一次同步周期）之后才把签发权切到新 key；截止时刻落在 `pending-activation.record` 里，重启和第二实例按同一份 `activate_at` 恢复，不会因为进程内 sleep 丢失。旧公钥继续留在验证窗口内。`KEY_ACTIVATION_DELAY_SECONDS` 的生产范围是 `65` 到 `300`，且不能超过保留窗口；低于 `65` 会使服务启动失败，只有内部测试构造器允许 `0`。进行中的轮换不受中途改配置影响。因此多实例共享同一目录时，某个实例的轮换或吊销最迟在一个同步周期后在其他实例生效，期间旧公钥仍在保留窗口内可验签。管理 API 有两条独立通道：系统 `ADMIN_TOKEN` Bearer，以及浏览器 HttpOnly Session Cookie（写操作还需 CSRF Cookie 与 `X-CSRF-Token` 绑定，权限按用户角色判定）。`ADMIN_TOKEN` 为空时关闭整个已初始化的管理面：Bearer 与浏览器管理 Session 都返回 `403 admin_disabled`；不存在 Owner 时公开的首个 Owner 初始化接口仍是唯一例外。此时启动日志会记录一条 `ADMIN_TOKEN not set` 警告，明确说明整个管理 API 已关闭，避免运维误判仍可通过 Session 管理。

运行期 Issuer 是 OIDC 发行者标识，会写入 JWT 的 `iss` claim 和 Discovery 文档，必须是无 path、query 和 fragment 的固定绝对 URL，且不能从请求 Host 或反向代理输入推导。它保存在 PostgreSQL `app_settings`，由 Owner 管理设置写入并由运行时热更新。未配置时服务进入保护模式：健康检查、静态前端、首 Owner bootstrap、ID=1 Owner 登录以及未依赖正式 Issuer 的管理路径仍可用；注册、普通用户创建、管理员/Owner 创建关闭，OAuth/OIDC、Discovery、JWKS 和外部登录路由关闭。旧环境变量 `APP_ISSUER` 只在数据库为空时导入一次，不能覆盖已经持久化的值，也不是新部署配置路径。

HTTPS 部署的 Session 和 CSRF Cookie 使用 `__Host-chenxing_session` 与 `__Host-chenxing_csrf`，固定带 `Secure; Path=/` 且不带 `Domain`，由浏览器强制 host-only 约束。外部 OAuth state Cookie 同样遵守这条契约：生产名称为动态的 `__Host-chenxing_external_oauth_state_<state 绑定标识>`，回调只读取该 host-only 名，同站兄弟域投下的父域 `Domain` cookie（普通 `chenxing_external_oauth_state_*` 名）不会命中。`COOKIE_SECURE=false` 只允许用于明确的 loopback HTTP 本地开发（`localhost`、`127.0.0.1` 或 `::1`），此时才使用不带 `__Host-` 的兼容名称；在 HTTPS 或其他主机发行者下会导致启动失败，生产路径不会回退到普通名。HTTP 发行者配合 `COOKIE_SECURE=true` 会记录启动警告，因为浏览器可能拒绝 Secure Cookie。

Session payload 使用 AES-256-GCM 并携带 key id。`AUTH_ENCRYPTION_KEY` 保留为单密钥兼容写法。轮换时设置逗号分隔的 `kid=<key-id>:<standard-base64-32-byte-key>` 密钥环 `AUTH_ENCRYPTION_KEYS`，并设置 `AUTH_ENCRYPTION_ACTIVE_KID`；新 Session 只使用 active key，旧 key 只读。旧 key 必须保留到最长 Session TTL 加 outbox 重试窗口结束后再移除；该重试窗口现在有明确上限（10 次尝试，约 20 分钟），超出后事件进入 dead-letter 而不是无限重试。回滚通过把旧 key 设为 `AUTH_ENCRYPTION_ACTIVE_KID` 并继续保留新 key 完成。移除 key 会故意使仅由该 key 加密的 Session 失效，请求返回 401 并清理浏览器 Cookie。Redis 只保存加密 payload，不保存 Session 或 CSRF 明文。

浏览器 Session 同时受绝对期限和空闲期限约束：`SESSION_TTL_SECONDS` 默认 7 天，是创建时固定的绝对截止时间；`SESSION_IDLE_TIMEOUT_SECONDS` 默认 1800 秒，成功认证请求在空闲窗口过半时更新 `last_seen_at`，但绝不会延长绝对截止时间。Redis 投影的 TTL 取这两个截止时间中较早者，PostgreSQL 是撤销、epoch 和空闲状态的权威来源。`SESSION_MAX_CONCURRENT_SESSIONS` 默认 5；新登录达到上限时，在同一用户事务锁内撤销最早的活跃 Session，再写入新 Session，并通过 outbox 删除旧 Redis 投影。Cookie 本身仍保留绝对生命周期，服务端 idle 校验负责缩短不活动凭据的有效窗口。三个会话配置项都有启动期上下界校验（绝对 TTL 90 天、空闲 30 天、并发 1000），越界直接拒绝启动——`SESSION_TTL_SECONDS` 会原样进入 Redis `SET ... EX`，Redis 整数上限是 i64，无上界的饱和值会让每次会话写入失败（#365）。

`session_outbox` 有明确的有界生命周期，分三个状态：待处理、已投递和 dead-letter。一个事件最多被投递 10 次（退避上限 5 分钟，覆盖约 20 分钟的真实故障窗口）；仍然失败则写入 `dead_lettered_at` 并退出待处理索引，不再被重试，`attempts` 和 `last_error` 作为审计记录保留。已投递事件保留 1 天，dead-letter 事件保留 30 天，都由 outbox worker 按 5 分钟间隔分批删除，每批每类上限 500 行，积压时连续清理直到收敛。撤销只在真正发生"未撤销 → 已撤销"转变时写入事件：重复登出和对不存在令牌的登出不产生投递任务。运维应监控 dead-letter 行——一条撤销事件进入 dead-letter 意味着对应的 Redis 投影可能仍然存在，需要人工确认，而 PostgreSQL 始终是认证判定的权威来源，投影残留不会让已撤销的会话通过认证。

没有已启用认证因子的新账号，密码验证成功后直接获得普通已认证 Session；TOTP 和 WebAuthn passkey 都是可选的，登录后可在账户安全设置中启用。启用后，后续密码登录会通过短期 HttpOnly pending-login Cookie 进入因子流程：Redis 中的 `login_ticket` 绑定同一浏览器 holder，前端需要完成已绑定的 TOTP 或 passkey 验证后才会获得 Session。生产环境应设置固定的 `WEBAUTHN_RP_ID` 和 `WEBAUTHN_ORIGIN`；Issuer 配置完成后，未显式覆盖的值从运行时 Issuer 派生，不能从请求 Host 派生。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。除非另有明确说明，项目中的源代码和文档均按该许可证发布。
