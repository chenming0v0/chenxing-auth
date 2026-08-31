# Issue 006: 管理后台统计、用户与系统设置

## 目标

将 `/admin`、`/admin/users`、`/admin/settings` 接入管理身份、权限隔离、分页
查询和系统配置 API。系统设置、身份提供商、套餐定义和登录/MFA 限流均为 Owner-only；
邀请码、钱包兑换码等运营设置仍使用 `ManageSettings`，用户/Client/审计沿用各自权限。

## 前端接入位置

- `web/src/pages/admin.tsx`：仪表盘聚合统计、用户查询/操作、注册策略、Issuer
  和密钥轮换状态。
- `web/src/components/shells.tsx`：管理入口仅在有 `AdminPermission` 的会话中可见，
  并处理管理员退出。

## API

- `GET /api/v1/admin/auth/me`：管理员 id、email、role、explicit permissions、状态和
  管理 Session 过期时间。
- `GET /api/v1/admin/overview`：用户、Client、管理员和审计聚合计数。
- `GET /api/v1/admin/users/query?page&page_size&search&status`：分页用户目录，响应
  `{ items, page, page_size, total }`。
- `GET /api/v1/admin/clients/query?...`：分页 Client 目录，不返回 Secret。
- `GET /api/v1/admin/audit/query?page&page_size&action&resource_type`：分页审计数据。
- 用户写操作：`POST /api/v1/admin/users/{user_id}/{status}`、`/role`、`/plan`。
- 套餐管理：`GET/POST/PUT /api/v1/admin/plans`、`/{id}/archive`、`/{id}/restore`。
- 系统设置：对应 OpenAPI 的 `/api/v1/admin/settings/*`；密钥轮换使用
  `POST /api/v1/admin/keys/rotate`。

## 接入要求

- `ADMIN_TOKEN` 为空时，除无 Owner 的首次 bootstrap 外，管理接口一律拒绝；不能
  用前端空 token 绕过。
- 每个按钮按 `AdminPermission` 显示/禁用，不能只依赖路由可见性；Owner-only 入口对普通
  Admin 隐藏，服务端必须再次拒绝。
- 浏览器 Session 管理写操作必须同时校验管理员 HttpOnly Cookie、CSRF Cookie 和
  `X-CSRF-Token`；Bearer 只用于设计好的 API 客户端场景。
- 所有查询使用服务端分页，前端搜索长度和 page bounds 与 OpenAPI 约束一致。
- 不渲染密码哈希、Client Secret、私钥或原始敏感审计值。

## 验收

- 无权限管理员看到空值或受限状态，不出现 403 后的半更新数据。
- 搜索、分页、状态过滤保持 query string 可复制、可刷新。
- 系统设置保存后重新拉取服务端值；密钥轮换响应不包含私钥材料。
