# Issue 003: 套餐与权益用量

## 目标

让 `/console` 的配额摘要与 `/console/plans` 的套餐页面使用真实权益数据，
并为升级动作保留清晰的后端工作边界。

## 前端接入位置

- `web/src/pages/console/account.tsx`：`ConsoleOverview` 的配额进度、
  `ConsolePlans` 的当前套餐和选择按钮。
- `web/src/data.ts`：删除演示套餐与统计常量，替换为 API response 映射。

## API

- `GET /api/v1/auth/entitlements`：当前生效套餐、每个权益的 `limit`、`used`、
  `remaining`；`limit: null` 表示无限。
- 管理端后续由独立管理 issue 接入 `GET/POST/PUT /api/v1/admin/plans`、
  `/archive`、`/restore`。

## 接入要求

- 用后端返回的 `used / limit` 计算进度，不能把前端常量当作配额事实。
- 处理无限配额、缺失 limit、已归档套餐和响应为空的状态。
- “选择方案”先调用产品定义的升级流程；当前页面不能宣称已扣款或已升级。
- 额度数字应避免过度精确的动画，确保移动端不发生布局跳动。

## 验收

- 总览和套餐页使用同一份权益缓存，切换页面不出现互相矛盾的数字。
- 达到配额时显示可理解的限制状态，并提供支持/升级入口。
- 未授权响应回登录页，其他错误保留可重试状态。
