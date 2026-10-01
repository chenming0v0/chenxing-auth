# 辰星双 APK 登录票 v2

实施依据：2026-09-28 冻结的四仓 `dual-app-login-v2.md`。本文只说明 auth 边界；不表示已部署或已完成四仓运行验证。

## HTTP 与信任来源

`POST /api/v2/auth/chenxing/exchange`，`Authorization: Bearer <普通 OAuth AT>`：

```json
{"app_kind":"chrome_termux","device_id":"安装 UUID","device_info":null,"provider":"cltermux"}
```

- JSON 严格拒绝未知、重复、缺失和类型错误字段。`app_kind` 仅 `chrome_termux|termux_chrome`。
- `device_id` 非空、最多 255 UTF-8 字节、无控制字符，不 trim/折叠；`device_info` 可省略/null，字符串最多 1024 字节。
- provider 沿用现有选择规则：与当前有效 scopes 匹配的资源服务唯一时可省略，多候选返回 400，必须明确 slug。最终选中的服务必须声明 `cltermux:access`。
- 从已验签 AT 的单字符串 `aud` 经现有 `ClientService::find_registered` 读取活跃 OAuth Client。只使用 Owner 在 Android Asset Links 管理面登记的声明：`top.clyact → chrome_termux`、`com.termux → termux_chrome`。无声明、其他包、非活跃 Client、与输入不一致均拒绝；不接受请求包名、不另建配置或硬编码生产 client ID。
- 保留 AT 撤销、实时同意和 scope 收窄、资源服务 allowlist、启用状态、辰星用户状态、live 关联、提供方账号状态和 subject 限流。关联 UID 只接受 `cltermux:[1-9][0-9]*`。

成功响应恰好六字段：

```json
{"v":2,"login_ticket":"<RS256 JWT>","uid":"cltermux:42","app_kind":"chrome_termux","device_id":"安装 UUID","expires_at":"2026-09-28T12:05:00Z"}
```

所有响应含 `Cache-Control: no-store` 和 `Pragma: no-cache`。错误沿用 auth 顶层 `{"code":"...","message":"安全说明"}`，不是 Account Provider 的嵌套 `error` 信封。OpenAPI 中专用 `ChenxingExchangeError` 描述稳定枚举；没有修改平台通用提取器或 OAuth 错误语义。

| HTTP | code |
| --- | --- |
| 400 | invalid_json（JSON 语法）；invalid_request（请求结构/字段/上限/媒体类型/候选歧义） |
| 401 | invalid_chenxing_token |
| 403 | app_not_allowed / insufficient_scope / account_not_linked / account_disabled |
| 410 | protocol_retired，仅旧 v1 |
| 429 | rate_limited |
| 503 | provider_unavailable（存储、限流或签名不可用）/ service_unavailable（Issuer/超时） |

`POST /api/v1/auth/chenxing/exchange` 无条件 410，不认证、不解析 body、不依赖 Issuer、不重定向、不保留旧兑换旁路。

## 票据不是会话

RS256、`typ=JWT`、已发布 `kid`；完整 claims：`iss`、单字符串 `aud`、`sub`、整数 `v=2`、`token_use=cltermux_login`、`uid`、`binding_id`、正整数 `binding_version`、`scope=cltermux:access`、`app_kind`、精确 `device_id`、整数 `iat`、`exp`。签发时固定 `exp-iat=300`，接收方到期无宽限。`binding_version` 是门户关联代数，不是 Go 设备 epoch。

普通 OAuth AT 的签发形状不变。两个 AT 解码入口统一按字段存在性（含 null）拒绝 `v/token_use/uid/binding_id/binding_version/app_kind/device_id`，覆盖 UserInfo GET/POST、撤销 AT 分支和本兑换端点。旧绑定票也不可充当 AT。RFC 7009 对未知票仍返回 200，但不把票登记为被撤销的普通 AT。

客户端仅在内存持有票，再向 Go v2 换取本地 session。只有 Go 返回的 session 能用于业务。允许同设备有效票重试；不承诺一次消费。auth 不新增设备表、不占设备槽、不提供/请求设备 reset。

## Account Provider 保持独立

账号关联、同步、刷新、解除和撤销 outbox 保持原协议，不接设备重置。两产品快照复用现有 `fields[].type=status`：

- `chrome_termux_login` / 浏览器版登录状态
- `termux_chrome_login` / WebView 版登录状态

值为 `unbound|logged_out|logged_in`。旧待认领占用省略两字段；未知/缺失不能推断为未绑定；这些是最近同步快照而非实时在线。新增独立产品 fixture，通用提供方 fixtures 和 schema 不变，无迁移。

## 验证交接

本实施 lane 只运行 `cargo fmt --check`、OpenAPI/fixture 静态检查及 src 行数检查，不执行任何生成 target 的命令。
所有 lane 写入终态后，由主会话串行执行（仅隔离测试数据库/Redis，禁止生产 DSN）：

```bash
cargo check
./test_sh/test.sh --lib
./test_sh/test.sh --test identity --test oauth
```

重点：`resource_service_exchange::*`、`resource_service_account_disabled::*`、`resource_service_binding::*`、`csrf_route_coverage::*`、`tokens::*`、`resource_services::snapshot_tests::*`。需要缩小测试时由主会话使用自己的 `CHENXING_TEST_ROLE=orchestrator` 与脚本 `-E` 筛选；本 lane 不代跑。

API.md 位于授权写入范围外，未修改；此页承接本次接入说明。生产注册、Go allowlist、真机及协调发布由主会话跟踪，未改部署配置。
