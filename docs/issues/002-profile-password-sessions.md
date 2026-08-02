# Issue 002: 个人资料、密码与会话管理

## 目标

让 `/console/profile` 的基本资料、安全设置和会话区域对接用户中心 API，
并保持浏览器写操作的三件套校验。

## 前端接入位置

- `web/src/pages/console/account.tsx`：`ConsoleProfile` 的资料保存、密码修改、
  会话列表和撤销操作。
- `web/src/api.ts`：所有 `PATCH`、`POST`、`DELETE` 请求共用 CSRF 头。

## API

- `GET /api/v1/auth/me`：加载资料与当前 Session 过期时间。
- `PATCH /api/v1/auth/me`：body `{ display_name }`，保存后更新页面状态。
- `POST /api/v1/auth/password`：body `{ current_password, new_password }`，成功
  后所有用户 Session 会被撤销。
- `GET /api/v1/auth/sessions`：加载只包含元数据的会话列表。
- `DELETE /api/v1/auth/sessions/{session_id}`：撤销指定会话。

## 接入要求

- 不展示密码哈希、Session payload、IP 或 User-Agent 等敏感基础设施数据。
- 密码修改成功后清空本地用户状态；当前会话被撤销时返回登录页。
- `session_id` 按整数路径参数传递，撤销动作必须带 Session Cookie、CSRF Cookie
  和 `X-CSRF-Token`。
- 后端错误码映射为字段级提示或通用错误，不直接显示 SQL / 堆栈。

## 验收

- 资料修改刷新后仍显示服务端结果。
- 密码错误不会烧掉有效会话；成功修改才触发全量撤销。
- 可区分当前会话与其他会话，撤销后列表即时刷新。
