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
- 配置驱动的自定义 OAuth/OIDC 提供商管理、加密 Client Secret、外部身份绑定和浏览器回调登录

后续增强方向：

1. 将管理后台入口从轻量服务端 HTML 扩展为完整前端应用。
2. 增加更多真实 OIDC Provider/Client 互操作测试和限流策略。
3. 将签名私钥接入外部受保护密钥存储，并增加密钥撤销策略。
4. 为业务子项目提供经过评审的具体扩展实现。

## 本地开发

### 前置条件

- Rust 1.94 或兼容的稳定版工具链
- Node.js 22 或兼容版本及 npm
- PostgreSQL 14 或更高版本
- Redis 6 或更高版本

复制 `.env.example` 为 `.env`，按本地环境修改连接地址。使用 HTTP 本地开发时，将 `APP_ISSUER` 设置为 `http://127.0.0.1:3000`（或其他 loopback 地址）并将 `COOKIE_SECURE` 显式设为 `false`；HTTPS 或非 loopback 环境必须保持 `COOKIE_SECURE=true`。正常服务启动不会修改数据库结构；需要执行迁移时运行 `cargo run -- migrate`，生产 Docker 部署脚本会在启动应用前显式执行同一迁移命令。审计归档不在 Web 服务启动时自动运行，只有单独的 `cargo run -- audit-archive` 维护命令会搬运过期热表事件。

数据库连接分成两个用途不同的池。请求路径使用的应用池会在每条新连接上设置服务端 `statement_timeout`，默认 `DB_STATEMENT_TIMEOUT_MS=5000`（允许 100 至 60000 毫秒）：`REQUEST_TIMEOUT_SECONDS` 只放弃 HTTP 响应，PostgreSQL 后端仍在执行，连接不会归还，因此语句上限必须由数据库自己执行，否则少量卡住的查询就能抽干连接池并让登录和令牌签发一起失败。该变量取值越界或不是整数时直接启动失败，不静默回退，避免运维以为自己配置的上限生效；设为 `0` 表示显式关闭（仅在数据库角色已带 `ALTER ROLE ... SET statement_timeout` 时使用），启动时会记录警告。`migrate` 和 `audit-archive` 走独立的维护池，不带 `statement_timeout`，长时间 DDL 和归档批次不会被中途取消。

#### 快速启动

项目根目录提供三份开发脚本：

- `./dev.sh` — 一键启动完整开发环境（Docker 基础设施 + 前后端），`Ctrl+C` 只停止前后端，Docker 容器保持运行
- `./dev-docker.sh` — 仅启动 PostgreSQL 和 Redis（分离模式），脚本退出后容器继续运行
- `./dev-services.sh` — 仅启动前后端（需要先启动 Docker 基础设施），`Ctrl+C` 停止前后端

日常开发推荐工作流：每日首次启动运行 `./dev.sh`，后续代码修改后只需 `Ctrl+C` 停止前后端再重新运行 `./dev-services.sh`，无需反复重启数据库容器。停止 Docker 服务使用 `docker compose down`。

认证失败限流由 Redis Lua 脚本在单次原子操作中完成计数、窗口 TTL 和阈值判定。生产默认使用 `AUTH_LIMITER_FAILURE_POLICY=fail-closed`：Redis 不可用时认证请求不会被放行，并记录结构化 `auth_limiter.redis_unavailable` 事件；只有在明确接受降级风险时才使用 `fail-open`。`AUTH_LIMITER_MISSING_SOURCE_IP=reject` 是生产默认值，防止没有可信 `ConnectInfo` 的请求共用全局 `unknown` 桶；`skip` 只跳过 IP 维度，仍保留 account、ticket 限流，并应仅用于明确配置的测试或受控入口。限流日志只记录维度、窗口和不可逆 key hash，不记录账户、ticket、IP 原文或认证凭据。
迁移编号在合并时必须保持唯一且连续：sessions lane 使用 `0006_session_epochs.sql` 和 `0014_session_idle_policy.sql`，plans lane 使用 `0007_plan_default_invariant.sql`，本 lane 的管理员查询索引使用 `0008_admin_query_indexes.sql`，审计不可变性和归档边界使用 `0013_audit_append_only_retention.sql`。不要复用已占用的编号或修改已有迁移的 SQL 内容。

本次统一身份数据库重构使用新的单一基线迁移，不支持保留旧开发数据滚动升级。旧数据库中的 `_sqlx_migrations` 记录也不能被这条新基线自动转换；生产环境部署遇到迁移失败时必须先备份并执行经过批准的数据迁移或重建方案。首次在本地切换到该版本时，请确认 Compose 项目为本仓库的 `chenxing-auth` 后执行 `docker compose down -v`，再运行 `docker compose up -d postgres redis`；该操作会删除本地 PostgreSQL/Redis 开发数据，生产环境不得照此操作。

审计事件由 `audit_events` 和 `audit_events_archive` 两张表保存。迁移创建的数据库触发器拒绝两张表的 `UPDATE`、`DELETE` 和 `TRUNCATE`；生产安装还会把 migration/owner role 与 `chenxing_runtime` 分离，runtime role 对两张审计表没有任何修改权限，归档只通过固定 `search_path` 的最小权限 `SECURITY DEFINER` 函数完成。触发器保留为纵深防御，不再作为唯一边界。归档先复制后删除，且只删除已成功复制的行；归档表本身永久保留并拒绝修改。审计查询会合并两张表。

`AUDIT_ARCHIVE_ENABLED` 默认是 `false`。明确设置为 `true` 后，`AUDIT_RETENTION_DAYS`（默认 2555 天，允许 1 至 36500 天）定义事件留在热表的最短时间；超过该窗口的事件只是被搬到永久归档表，不会被物理丢弃。Web 请求和正常服务进程不会执行清理，部署必须由一个外部 cron/systemd 任务定期运行 `cargo run -- audit-archive`（Docker 部署使用 `docker compose --env-file .env -f docker-compose.prod.yml run --rm app audit-archive`）。每次命令最多处理 1000 行，重复调用安全；命令日志只记录批次数和保留窗口，不记录 action、resource、metadata 或其他事件内容。不要让多个部署副本各自建立定时器，也不要在未确认合规窗口前缩短保留天数。回滚迁移前先停用调度器，并按迁移注释把归档行恢复到热表，再按逆序删除对象。

`cargo build`/`cargo run` 在缺少 `web/dist/index.html` 时会通过 Cargo build script 自动安装并构建 Web。GitHub Actions 发布流水线会先构建一次前端产物，再在各目标平台复用；推送到 GHCR 的多架构镜像只打包已经编好的 Linux 二进制，不再在容器里二次 `cargo build`。本地 `docker compose` 仍使用源码版 `Dockerfile` 现场编译。启动后访问 `http://127.0.0.1:3000/` 即可同时使用 Web 和 API。

## API 文档

- [给人看的 API 文档](https://wiki.auth.clya.top)
- [给 AI 看的 API 文档](https://wiki.auth.clya.top/llms.txt)


以下能力仍属于后续增强项，当前不应直接视为完整生产认证产品：

- 用户已授权应用的聚合列表 API（当前页面明确展示后端能力边界）
- 大规模第三方 OAuth/OIDC 互操作认证矩阵
- 密钥撤销策略和外部受保护密钥存储
- 生产级限流、告警和密钥托管集成

## Docker 部署

服务器安装 Docker Engine、Docker Compose v2 和 `curl` 后，在项目根目录执行：

```bash
./deploy/install.sh
```

脚本首次运行会生成权限为 `0600` 的 `.env`，随机生成 PostgreSQL 密码、runtime 数据库密码和 `ADMIN_TOKEN`，先校验生产 Compose 配置，再启动 PostgreSQL、Redis 和认证服务，并等待 `/health` 返回成功。已有 `.env` 不会被覆盖，但缺少 runtime 角色凭据时会自动追加；`APP_ISSUER` 是必填项，生产环境必须设置为固定的 HTTPS 地址（例如 `https://auth.example.com`），未设置或为空时服务启动即失败，并将 `.env` 作为秘密文件保护。升级 v1.0.6 数据库时，安装脚本会先运行 `deploy/repair-v106-checksum.sql` 修复被原地修改的迁移元数据。健康检查失败时脚本会输出 Compose 状态和应用日志，便于定位启动问题。

生产 Compose 文件为 `docker-compose.prod.yml`。数据库、Redis、JWK 密钥和内嵌 Web 都由应用容器提供，应用容器以非 root 用户运行。TLS 终止可以交给服务器网关，但 Web/API 本身不依赖反向代理。

## GitHub Actions

当前 `/oauth/authorize` 同时支持开发期 `X-Chenxing-Session` 和 HttpOnly Session Cookie；带 `Accept: text/html` 的浏览器流程会进入登录页和授权确认页。浏览器 Cookie 会话的状态变更必须携带 `X-CSRF-Token`，并与 CSRF Cookie 和 Session 中的 Token 一致。管理 API 复用普通用户 Session 和 CSRF Cookie，角色决定管理权限。

`KEY_DIRECTORY` 默认指向 `data/keys`，该目录包含运行时私钥并已加入 `.gitignore`。Unix 下应用会将目录收紧为 `0700`，私钥、active `kid` 和 OAuth Provider 主密钥收紧为 `0600`，并在启动时修正已有过宽权限。密钥写入使用受限临时文件和原子替换。active `kid` 存在但它指向的私钥材料不在目录里时，服务 fail-closed：启动和刷新直接失败并记录一条不含密钥材料的 error 日志，既不覆盖 `kid` 也不生成替代密钥，避免静默作废全部已签发令牌并抹掉材料丢失的证据；只有目录既没有 `kid` 也没有任何私钥材料时才执行首次初始化。恢复方式是还原备份的私钥文件，或在确认可以接受全部已签发令牌失效后手动清空密钥目录。`KEY_ROTATION_GRACE_SECONDS` 默认是 `604800`（7 天），支持范围是 `1` 到 `2592000` 秒（30 天），且不能小于 access/ID token TTL：轮换后的旧公钥在该窗口内继续用于验签，窗口外的旧私钥会在启动或后续轮换时回收；设置为 `0` 或超出范围会使服务启动失败。签发、验签和 JWKS 三条请求热路径只读进程内的密钥快照，不在请求线程里读写密钥目录；与共享 `KEY_DIRECTORY` 的一致性由一个 5 秒周期的后台任务负责（验签遇到未知 `kid` 时会提前触发一次同步）。因此多实例共享同一目录时，某个实例的轮换或吊销最迟在一个同步周期后在其他实例生效，期间旧公钥仍在保留窗口内可验签。`ADMIN_TOKEN` 为空时，管理 API 默认全部拒绝访问，唯一例外是不存在 Owner 时公开的首个 Owner 初始化接口；此时启动日志会记录一条 `ADMIN_TOKEN not set` 警告，便于运维感知管理面不可用。

`APP_ISSUER` 是必填配置项，没有默认值：它是 OIDC 发行者标识，会写入 JWT 的 `iss` claim 和 Discovery 文档，必须是无 path、query 和 fragment 的绝对 URL，且不能从请求 Host 或反向代理输入推导。未设置、为空或格式非法时服务启动失败，不再回退到 `http://<APP_HOST>:<APP_PORT>`。

HTTPS 部署的 Session 和 CSRF Cookie 使用 `__Host-chenxing_session` 与 `__Host-chenxing_csrf`，固定带 `Secure; Path=/` 且不带 `Domain`，由浏览器强制 host-only 约束。`COOKIE_SECURE=false` 只允许用于明确的 loopback HTTP 本地开发（`localhost`、`127.0.0.1` 或 `::1`）；在 HTTPS 或其他主机发行者下会导致启动失败。HTTP 发行者配合 `COOKIE_SECURE=true` 会记录启动警告，因为浏览器可能拒绝 Secure Cookie。

Session payload 使用 AES-256-GCM 并携带 key id。`AUTH_ENCRYPTION_KEY` 保留为单密钥兼容写法。轮换时设置逗号分隔的 `kid=<key-id>:<standard-base64-32-byte-key>` 密钥环 `AUTH_ENCRYPTION_KEYS`，并设置 `AUTH_ENCRYPTION_ACTIVE_KID`；新 Session 只使用 active key，旧 key 只读。旧 key 必须保留到最长 Session TTL 加 outbox 重试窗口结束后再移除。回滚通过把旧 key 设为 `AUTH_ENCRYPTION_ACTIVE_KID` 并继续保留新 key 完成。移除 key 会故意使仅由该 key 加密的 Session 失效，请求返回 401 并清理浏览器 Cookie。Redis 只保存加密 payload，不保存 Session 或 CSRF 明文。

浏览器 Session 同时受绝对期限和空闲期限约束：`SESSION_TTL_SECONDS` 默认 7 天，是创建时固定的绝对截止时间；`SESSION_IDLE_TIMEOUT_SECONDS` 默认 1800 秒，成功认证请求在空闲窗口过半时更新 `last_seen_at`，但绝不会延长绝对截止时间。Redis 投影的 TTL 取这两个截止时间中较早者，PostgreSQL 是撤销、epoch 和空闲状态的权威来源。`SESSION_MAX_CONCURRENT_SESSIONS` 默认 5；新登录达到上限时，在同一用户事务锁内撤销最早的活跃 Session，再写入新 Session，并通过 outbox 删除旧 Redis 投影。Cookie 本身仍保留绝对生命周期，服务端 idle 校验负责缩短不活动凭据的有效窗口。

用户首次密码登录会通过短期 HttpOnly pending-login Cookie 进入因子流程；Redis 中的 `login_ticket` 绑定同一浏览器 holder，前端需要完成 TOTP 或 WebAuthn passkey 注册后才会获得 Session。后续登录需要密码加已绑定的 TOTP 或 passkey。生产环境应设置固定的 `WEBAUTHN_RP_ID` 和 `WEBAUTHN_ORIGIN`，默认从固定 `APP_ISSUER` 派生，不能从请求 Host 派生。

## 开源协议

本项目采用 [MIT License](LICENSE) 开源。除非另有明确说明，项目中的源代码和文档均按该许可证发布。
