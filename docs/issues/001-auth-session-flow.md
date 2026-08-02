# Issue 001: 接入注册、登录与浏览器会话

## 目标

把 `/register`、`/login`、`/console` 的演示状态替换为真实身份流程，覆盖
注册、登录、Session Cookie、CSRF Cookie 和未登录重定向。

## 前端接入位置

- `web/src/pages/auth.tsx`：`AuthPage` 的注册和登录表单提交。
- `web/src/components/shells.tsx`：登录态判断、退出登录和账户菜单。
- `web/src/App.tsx`：受保护路由的 loading / unauthenticated 分支。
- `web/src/api.ts`：复用 `apiFetch`，保持 `credentials: include` 和写请求的
  `X-CSRF-Token`。

## API

- `POST /api/v1/users`：注册，body 使用 OpenAPI 的 `RegistrationInput`。
- `POST /api/v1/auth/login`：登录，body 使用 `LoginInput`；处理 `200` 成功和
  `202` 需要因子认证两种结果。
- `GET /api/v1/auth/status`：应用启动时检查当前 Session。
- `GET /api/v1/auth/me`：登录后加载公开用户资料。
- `POST /api/v1/auth/totp/login`：登录返回 `202` 时完成 TOTP。
- `POST /api/v1/auth/totp/setup`、`/setup/confirm`：首次因子绑定。

## 接入要求

1. 不读取或展示 Session Cookie 内容；所有请求使用 `credentials: include`。
2. 写操作由 `apiFetch` 从 CSRF Cookie 读取值并设置 `X-CSRF-Token`。
3. 认证失败使用通用错误文案，不暴露邮箱是否存在或内部错误。
4. 登录成功后刷新 `/api/v1/auth/me`，不要用表单输入自行拼接身份状态。

## 验收

- 未登录访问控制台会回到 `/login`，登录后回到原始路径。
- 登录响应为 `202` 时能进入 TOTP 页面，不能提前创建 Session。
- 退出登录清理本地状态并返回首页；敏感值不写入日志。
