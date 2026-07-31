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

## 强制要求

- 之后的模型在写任何卡片或容器时，必须使用 `.chenxing-hud-panel`。
- 禁止另建玻璃卡片样式，禁止把 `chenxing-glass-strong chenxing-hud-frame p-8` 拆开重复使用。
- 容器默认不设窄宽度；宽度用 `w-full`、`max-w-*` 或父级网格控制。
- 新页面必须引用 `partials/hud-panel.html`，只填充 `hudPanelContent` 插槽。
- CSS 修改只改 `colors_and_type.css`，改完执行 `fill-html-head.mjs --replace-head`。
- 完成设计稿后执行 `scan-design-directory.mjs` 校验。
