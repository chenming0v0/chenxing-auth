# 辰星认证中枢 · 设计稿规范

## 公共玻璃容器（强制）

所有设计稿、HTML 页面、卡片、表单面板、对话框等 UI 容器必须使用公共容器：

```html
<div class="chenxing-hud-panel">
  <!-- 内容 -->
</div>
```

- 公共类：`.chenxing-hud-panel`
- CSS 唯一来源：`design-auth-chengming/colors_and_type.css`
- 共享片段：`design-auth-chengming/partials/hud-panel.html`，插槽为 `hudPanelContent`
- 视觉效果：strong glass 磨砂背景、青色左上/右下角标高光、默认 `2rem` 内边距

## 公共按钮与徽章（强制）

按钮和徽章必须使用公共样式类，禁止手写内边距/布局的临时按钮：

```html
<button class="chenxing-btn-primary"><i data-lucide="save" class="h-4 w-4"></i>保存</button>
<button class="chenxing-btn-ghost">取消</button>
<span class="chenxing-badge">未启用</span>
<span class="chenxing-badge-success"><i data-lucide="check" class="h-3.5 w-3.5"></i>已启用</span>
<span class="chenxing-badge-warning">已限流</span>
<span class="chenxing-chip">当前套餐</span>
```

- 公共类自带布局（inline-flex + gap + 默认内边距 + `white-space: nowrap`），图标和文字永不换行叠字；使用时不要再加 `px-* py-*`，需要拉伸用 `w-full`。
- `.chenxing-badge-success` / `.chenxing-badge-warning` 可单独使用，无需再叠加 `.chenxing-badge`。
- 需要新按钮变体时先扩展 `colors_and_type.css` 里的公共类，再同步到各页面内联样式，禁止在单页里手写一次性按钮样式。

## 公共侧边栏（强制）

修改侧边栏必须使用公共侧边栏，唯一来源是 `partials/sidebar.html`：

- 任何侧边栏改动（增删入口、调整分组、改图标或文案）**只能先改 `partials/sidebar.html`**，再把改后的 `<aside>` 原样同步到所有控制台/后台页面；禁止只改某一个页面里的侧边栏副本。
- 各页面对侧边栏唯一允许的差异是 `aria-current="page"` 高亮位置；其余内容必须与 `partials/sidebar.html` 逐字一致。
- 禁止在任何页面另建侧边栏结构、私自增删入口或调整分组顺序。
- 侧边栏结构变动后必须同步更新 `.design` 文件中所有页面卡片的交互连线（`data-dom-id` ↔ `targetPageId`）。

## 控制台/后台布局规范（强制）

- 控制台与后台页面一律不使用底部导航栏（`.chenxing-bottom-nav` / `.chenxing-bottom-tab`）和发光用户卡片（`.chenxing-userchip-glow`）；导航只保留左侧边栏 `.chenxing-sidebar`，任何断点下都不得重新引入底部栏或用户卡片。
- 全站共用**同一个**侧边栏，唯一来源是 `partials/sidebar.html`；所有控制台/后台页面必须原样复制它，只允许改动 `aria-current="page"` 的位置，禁止按页面增删入口或另起分组结构。
- 统一侧边栏分区顺序（上用户、下管理）：
  1. **账户**：总览、套餐与权益、个人信息、已授权应用
  2. **开发者**：接入应用、授权测试
  3. **管理**：仪表盘、用户管理
  4. **系统**：系统设置（永远在最下面，不放在顶部）
- 后台仪表盘页面为 `pages/admin-dashboard.html`（画布卡片 `page-admin-dashboard`）；新增页面时在统一侧边栏的对应分组补充入口，并同步所有页面与 `.design` 连线。

## 强制要求

- 之后的模型在写任何卡片或容器时，必须使用 `.chenxing-hud-panel`。
- 禁止另建玻璃卡片样式，禁止把 `chenxing-glass-strong chenxing-hud-frame p-8` 拆开重复使用。
- 容器默认不设窄宽度；宽度用 `w-full`、`max-w-*` 或父级网格控制。
- 新页面必须引用 `partials/hud-panel.html`，只填充 `hudPanelContent` 插槽。
- CSS 修改只改 `colors_and_type.css`，改完执行 `fill-html-head.mjs --replace-head`。
- 完成设计稿后执行 `scan-design-directory.mjs` 校验。
