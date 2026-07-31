# 前端 Plan：套餐与权益页

> 目标：控制台新增「套餐与权益」页，展示当前用户的套餐等级 + 各项资源用量。风格严格沿用现有深色扁平设计（`src/index.css` 的 panel / hairline / 单一 indigo accent，渐变只用于 hero）。

## 现状与关键约束

- 项目里**没有**套餐/权益的后端接口（`src/store.tsx`、`src/api.ts` 只有 user/clients/sessions）。
- 所以前端**先用清楚标注的预览数据**（`PREVIEW_ENTITLEMENTS`）把 UI 做出来，等后端 `GET /api/v1/auth/entitlements` 好了，改 `api.ts` + `store.tsx` 一处即可切真数据。
- **不编造**产品里不存在的概念（不做邮箱/域名/存储那些）。只展示真实存在的四项：OAuth 应用数、每日授权、每月授权、最大并发。

## API 契约（与后端 plan 文档一致）

`GET /api/v1/auth/entitlements` 返回：
```jsonc
{
  "plan": { "code": "vip", "name": "VIP", "description": "…", "validity": "permanent" },
  "entitlements": [
    { "key": "oauth_clients", "label": "OAuth 应用数", "used": 1, "limit": 2 },
    { "key": "daily_auth",    "label": "每日授权调用", "used": 0, "limit": 2500 },
    { "key": "monthly_auth",  "label": "每月授权调用", "used": 2300, "limit": 50000 },
    { "key": "max_qps",       "label": "最大并发（请求/秒）", "used": 35 }
  ]
}
```
- `limit` 是数字 → 显示 `used / limit` + 进度条 + 剩余。
- `limit: null` → 显示 ∞，不画进度条。
- 无 `limit` 字段 → 只显示数字（QPS 这种）。

## 交付物

1. `web/src/pages/console/Entitlements.tsx`
   - `PageHeader` 标题「当前套餐与权益」。
   - **套餐 hero 卡**：indigo→blue 渐变（唯一允许渐变的 hero 面），显示 tier code（大写字母间距）、套餐名（大字）、description、右侧两枚半透明 chip（当前套餐 / 永久有效 或到期日）。皇冠图标用 lucide `Crown`。
   - **权益卡片网格**：`grid sm:grid-cols-2 lg:grid-cols-3`，每卡 `panel rounded-xl`。含 label、`used / limit`、进度条（<70% indigo，70-90% amber，>90% rose）、剩余文案。三种 limit 模式都要处理（数字 / ∞ / 无 limit）。
   - 数据源：先 import `PREVIEW_ENTITLEMENTS` 常量并在文件顶部用注释标注「TODO: 后端接口就绪后改用 store」。
2. 路由：`web/src/App.tsx` 加 `<Route path="entitlements" element={<Entitlements />} />`。
3. 导航：`web/src/pages/console/ConsoleLayout.tsx` 的 `NAV` 加一项 `{ to: "/console/entitlements", icon: <Crown/>, label: "套餐与权益", group: "账户" }`。

## 切真数据时（后端好之后，我来改）

- `api.ts` 加 `entitlements: () => request<EntitlementsResponse>("/api/v1/auth/entitlements")` + 类型。
- `store.tsx` 的 `refresh()` 里并入 entitlements，或页面内单独 `useEffect` 拉取（推荐后者，避免拖慢总览加载）。
- `Entitlements.tsx` 把 `PREVIEW_ENTITLEMENTS` 换成接口数据，加 loading / error 态（用现有 `Notice` 组件）。

## 不做

- 不做套餐购买 / 升级流程（后端没有）。
- 不做管理端套餐 CRUD 界面（那是后续单独任务，本页只读）。
