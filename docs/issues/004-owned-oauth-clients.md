# Issue 004: 用户 OAuth 应用与 Client Secret

## 目标

将 `/console/integrate` 和 `/console/apps` 从本地演示数据接入当前用户拥有的
OAuth 项目，覆盖创建、更新、启用、禁用、撤销授权和 Secret 轮换。

## 前端接入位置

- `web/src/pages/console/developer.tsx`：创建客户端草稿、应用列表与授权参数。
- `web/src/pages/console/account.tsx`：`AuthorizedApps` 的撤销动作。
- `web/src/components/ui.tsx`：`CopyValue` 只做用户主动复制，不持久化 Secret。

## API

- `GET /api/v1/auth/oauth-clients`：当前用户拥有的项目和配额使用量。
- `POST /api/v1/auth/oauth-clients`：body `ClientInput`；`201` 响应中的 Secret
  只返回一次。
- `PUT /api/v1/auth/oauth-clients/{client_id}`：更新名称、Redirect URI 等配置。
- `POST /api/v1/auth/oauth-clients/{client_id}/disable|enable`：状态切换。
- `POST /api/v1/auth/oauth-clients/{client_id}/rotate-secret`：返回新 Secret 一次。

## 接入要求

- 前端永远不显示 Secret 哈希；创建和轮换响应离开当前页面后不再可恢复。
- 严格展示服务端校验后的 Redirect URI；不要在客户端放宽通配规则。
- 创建时处理用户项目数量冲突和每日/月度授权配额错误。
- 所有写操作需要用户 Session Cookie、CSRF Cookie 和 `X-CSRF-Token`。
- 普通用户只能看到自己拥有的项目，不能使用列表接口推断其他用户数据。

## 验收

- 创建成功后显示一次性 Secret 的复制界面，并明确刷新即不可恢复。
- 禁用项目后不能继续用于授权，但项目配额统计仍计入已创建数量。
- 删除/撤销操作有确认步骤，错误响应不会误删本地列表。
