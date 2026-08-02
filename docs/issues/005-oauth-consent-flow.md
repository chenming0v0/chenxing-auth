# Issue 005: OAuth 账号选择、授权确认与回调

## 目标

把 `/oauth/account`、`/oauth/consent`、`/oauth/redirect` 接到受绑定的待授权
请求，实现一次性授权码的批准/拒绝和安全返回。

## 前端接入位置

- `web/src/pages/oauth.tsx`：加载授权请求、展示 Client / Redirect Host / Scopes、
  提交 approve / deny、处理已校验的回调地址。
- `web/src/pages/auth.tsx`：未登录时的登录/因子流程完成后回到 pending request。

## API

- 浏览器首先访问 `GET /oauth/authorize`，必须携带 `client_id`、严格匹配的
  `redirect_uri`、`response_type=code`、`scope`、`state`、PKCE `code_challenge`
  和 `code_challenge_method=S256`。
- `GET /api/v1/oauth/authorize/requests/{request_id}`：读取绑定到当前 Session 的
  待授权摘要。
- `POST /api/v1/oauth/authorize/requests/{request_id}`：body
  `{ decision: "approve" | "deny" }`，返回已校验的回调数据。
- `/oauth/token`：由后端客户端用授权码和 `code_verifier` 换 Token，前端不直接
  保存 Client Secret 或处理 token endpoint。

## 接入要求

- 只显示后端返回的 display name、redirect host 和 scopes；不回显授权码。
- approve / deny 必须由后端原子消费，重复提交显示已消费状态。
- 当前 Session 必须与 pending request 的绑定 Session 一致，CSRF 校验失败不能
  烧掉有效授权请求。
- 拒绝时保留原始 `state` 并返回协议安全的 OAuth error，不泄露 code。
- 授权配额超限返回可理解的限流提示；不要自动重试批准请求。

## 验收

- 未登录、过期、跨会话或已消费 request 都不能展示完整授权信息。
- 同意后只跳转到服务端校验过的 Redirect URI。
- PKCE verifier 在后端 token 交换时必需，前端测试页只生成展示用参数。
