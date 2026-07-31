---
name: design-canvas-format
description: "SOLO Design .design 画布项目格式规范。在创建、编辑、解析 .design 文件，或编写画布页面交互连线时使用。"
---

# SOLO Design `.design` 画布项目格式规范

本 skill 记录 SOLO Design 画布项目的 `.design` 文件格式、目录结构、页面交互连线机制，以及创建/编辑时的完整约定。

## 目录结构

一个标准的 `.design` 画布项目：

```
<project-name>/
├── <project-name>.design          # 项目蓝图文件（JSON）
├── pages/                          # 所有页面 HTML 文件
│   ├── page-a.html
│   ├── page-b.html
│   └── ...
├── partials/                       # 可复用的 HTML 片段（导航栏、公共组件等）
│   ├── navbar.html
│   └── ...
├── assets/                         # 图片等静态资源
│   ├── image.jpg
│   └── ...
└── PLAN.md                         # 可选，设计规划文档
```

## `.design` 文件完整格式

`.design` 是项目的核心蓝图文件，本质是 JSON，包含两个顶层字段：`data` 和 `config`。

```json
{
  "data": [
    // 所有画布卡片（页面、图片、组件等）
  ],
  "config": {
    // 项目全局配置
  }
}
```

### `data` 数组 — 画布卡片

每个元素代表画布上的一个卡片，支持以下类型：

#### 类型 1：页面卡片（type: "page"）

```json
{
  "id": "page-chat-list",
  "title": "会话列表",
  "type": "page",
  "version": 1,
  "createdAt": 1782698600000,
  "canvasData": {
    "x": 0,
    "y": 590,
    "group": 0
  },
  "devMetadata": {
    "htmlSrc": "pages/chat-list.html",
    "interactions": [
      {
        "domId": "nav-characters",
        "targetPageId": "page-character-list"
      },
      {
        "domId": "open-chat-1",
        "targetPageId": "page-chat-interface"
      }
    ]
  }
}
```

**字段说明：**

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | 是 | 页面唯一标识，全局唯一，建议用 `page-<name>` 格式 |
| `title` | 是 | 显示在画布上的中文名称 |
| `type` | 是 | 固定为 `"page"` |
| `version` | 是 | 版本号，从 1 开始 |
| `createdAt` | 是 | 创建时间戳（毫秒级 Unix timestamp） |
| `canvasData` | 是 | 画布坐标信息 |
| `canvasData.x` | 是 | X 坐标（像素） |
| `canvasData.y` | 是 | Y 坐标（像素） |
| `canvasData.group` | 是 | 分组编号，0 为默认组 |
| `devMetadata` | 是 | 开发元数据 |
| `devMetadata.htmlSrc` | 是 | 相对于项目根目录的 HTML 文件路径 |
| `devMetadata.interactions` | 是 | 交互跳转定义数组 |

#### 类型 2：图片卡片（type: "image"）

```json
{
  "id": "image-001",
  "title": "界面示意图 1",
  "type": "image",
  "version": 1,
  "createdAt": 1782731152407,
  "canvasData": {
    "x": 0,
    "y": 16000
  },
  "devMetadata": {
    "imageSrc": "assets/1111111.jpg"
  }
}
```

**字段说明：**

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | 是 | 图片唯一标识，建议用 `image-<序号>` 格式 |
| `title` | 是 | 显示名称 |
| `type` | 是 | 固定为 `"image"` |
| `version` | 是 | 版本号 |
| `createdAt` | 是 | 创建时间戳 |
| `canvasData` | 是 | 画布坐标信息（同页面卡片） |
| `devMetadata` | 是 | |
| `devMetadata.imageSrc` | 是 | 相对于项目根目录的图片路径 |

### `config` 对象 — 项目配置

```json
{
  "autoLayout": true,
  "deviceType": "mobile",
  "projectName": "项目名称",
  "designLibrary": {
    "name": "Vercel",
    "id": "dl_builtin_vercel",
    "version": null,
    "scope": "built-in-global",
    "path": "c:\\Users\\<user>\\.trae-cn\\design_libraries\\dl_builtin_vercel",
    "versionSource": "context"
  },
  "showEdge": false
}
```

**字段说明：**

| 字段 | 必填 | 说明 |
|------|------|------|
| `autoLayout` | 是 | 是否自动排列画布布局，`true` / `false` |
| `deviceType` | 是 | 设备类型，`"mobile"` / `"desktop"` |
| `projectName` | 是 | 项目名称（中文） |
| `designLibrary` | 是 | 关联的设计系统信息 |
| `designLibrary.name` | 是 | 设计系统名称（如 `"Vercel"`, `"Apple"` 等） |
| `designLibrary.id` | 是 | 设计系统 ID |
| `designLibrary.version` | 否 | 设计系统版本，无版本时为 `null` |
| `designLibrary.scope` | 是 | 作用域，`"built-in-global"` 为内置全局设计系统 |
| `designLibrary.path` | 是 | 设计系统在磁盘上的绝对路径 |
| `designLibrary.versionSource` | 否 | 版本来源标记 |
| `showEdge` | 否 | 是否显示画布连线，默认 `false` |

## 页面交互连线机制

页面之间的跳转通过 `devMetadata.interactions` 数组定义。

### 交互定义格式

```json
{
  "domId": "nav-characters",
  "targetPageId": "page-character-list"
}
```

| 字段 | 说明 |
|------|------|
| `domId` | HTML 页面中可点击元素的 `id` 属性值 |
| `targetPageId` | 目标页面的 `id`（必须在 `data` 数组中存在） |

### 工作原理

1. SOLO Design 前端读取 `.design` 文件
2. 根据 `htmlSrc` 字段加载并渲染每个页面的 HTML
3. 根据 `interactions` 定义，在画布上绘制页面之间的连线
4. 用户点击页面中 `id` 为 `domId` 的元素时，跳转到 `targetPageId` 对应的页面

### HTML 页面中的对应写法

在 HTML 页面中，需要给可交互元素设置 `id`：

```html
<!-- 底部导航栏 -->
<nav class="bottom-nav">
  <button id="nav-chat" class="nav-item active">
    <span class="nav-icon">对话</span>
    <span class="nav-label">会话</span>
  </button>
  <button id="nav-characters" class="nav-item">
    <span class="nav-icon">角色</span>
    <span class="nav-label">角色</span>
  </button>
  <button id="nav-presets" class="nav-item">
    <span class="nav-icon">预设</span>
    <span class="nav-label">预设</span>
  </button>
  <button id="nav-code" class="nav-item">
    <span class="nav-icon">代码</span>
    <span class="nav-label">代码</span>
  </button>
  <button id="nav-world" class="nav-item">
    <span class="nav-icon">世界</span>
    <span class="nav-label">世界书</span>
  </button>
</nav>

<!-- 会话列表项 -->
<div id="open-chat-1" class="chat-item">
  <div class="avatar">A</div>
  <div class="info">
    <div class="name">助手</div>
    <div class="preview">你好！</div>
  </div>
</div>
```

## 页面 HTML 文件规范

### 基本结构

每个页面 HTML 文件应包含完整的 HTML 结构，但不需要 `<html>` / `<head>` / `<body>` 标签（仅保留 body 内容片段）：

```html
<!-- pages/example.html -->
<div class="page">
  <!-- 顶部导航 -->
  <header class="top-nav">
    <h1 class="page-title">页面标题</h1>
  </header>

  <!-- 页面内容 -->
  <main class="page-content">
    <!-- ... -->
  </main>

  <!-- 底部导航 -->
  <nav class="bottom-nav">
    <!-- 导航按钮，每个带 id -->
  </nav>
</div>
```

### CSS 样式

页面样式可以内联在 `<style>` 标签中，也可以引用外部 CSS。SOLO Design 会自动加载设计系统的 CSS 变量和全局样式。

```html
<style>
.page {
  width: 375px;
  height: 812px;
  /* 使用设计系统的 CSS 变量 */
  background-color: var(--bg-primary);
  color: var(--text-primary);
}
</style>
```

### 可复用片段（partials）

多个页面共享的组件（如底部导航栏）可以放在 `partials/` 目录中。HTML 文件通过注释或实际复制的引用方式使用。

## 常见导航模式

### 底部 Tab 导航

适用于主页面之间的切换，每个页面都包含相同的底部导航，但各自的 `interactions` 指向相同的目标页面集：

```
会话列表 ──nav-characters──→ 角色列表
会话列表 ──nav-presets──→ 预设管理
会话列表 ──nav-code──→ 代码管理
会话列表 ──nav-world──→ 世界书
```

### 返回导航

适用于二级页面返回上一级：

```
角色列表 ──back-to-characters──→ 角色列表
预设配置 ──back-to-preset-manager──→ 预设管理
```

### 弹窗/面板

适用于覆盖层、对话框等：

```
聊天对话 ──open-settings──→ 设置侧边栏
设置侧边栏 ──close-settings──→ 会话列表
```

## 创建新页面的完整流程

1. 在 `pages/` 目录创建 HTML 文件（如 `pages/new-page.html`）
2. 在 HTML 中给可交互元素设置 `id`
3. 在 `.design` 文件的 `data` 数组中添加新卡片：
   ```json
   {
     "id": "page-new-page",
     "title": "新页面",
     "type": "page",
     "version": 1,
     "createdAt": <当前时间戳>,
     "canvasData": {
       "x": <X坐标>,
       "y": <Y坐标>,
       "group": 0
     },
     "devMetadata": {
       "htmlSrc": "pages/new-page.html",
       "interactions": [
         {
           "domId": "back-btn",
           "targetPageId": "page-parent"
         }
       ]
     }
   }
   ```
4. 在其他需要跳转到此页面的页面中，补充对应的 `interactions` 条目
5. 确保 `id` 在整个 `data` 数组中唯一

## 注意事项

- `.design` 文件中的 `id` 必须全局唯一，不能重复
- `interactions` 中的 `targetPageId` 必须在 `data` 数组中存在，否则连线无效
- `canvasData` 的坐标影响画布上的布局位置；`autoLayout: true` 时可自动排列
- `createdAt` 使用毫秒级时间戳（`Date.now()` 的输出）
- `htmlSrc` 和 `imageSrc` 路径相对于 `.design` 文件所在目录
- 修改 `.design` 文件后，SOLO Design 前端会自动重新渲染

## 工具脚本（`scripts/`）

路径（相对仓库根）：`.claude/skills/design-canvas-format/scripts/`  
默认操作的 `.design` 文件：`chenmumu5-redesign-mobile/chenmumu5-redesign-mobile.design`  
（由 `design_common.py` 自动解析，可在任意工作目录执行 Python。）

### 推荐流程

1. **改连线 / Tab 跳转前**：先读 `chenmumu5-redesign-mobile/interactions.md`（逻辑真源）。
2. **改完 HTML 或 `.design` 后**：
   ```bash
   python .claude/skills/design-canvas-format/scripts/validate_interactions.py
   ```
3. **若代码管理区被 SOLO Design 写乱**（常见：`open-code-regex` 回退、L2 脚本指向编辑页）：
   ```bash
   python .claude/skills/design-canvas-format/scripts/strip_legacy_interactions.py
   python .claude/skills/design-canvas-format/scripts/apply_canonical_code_interactions.py
   python .claude/skills/design-canvas-format/scripts/validate_interactions.py
   ```
4. **需要导出当前连线对照**：  
   `dump_interactions.py --page page-code` 或全文 `--markdown`。

### 脚本一览

| 脚本 | 用途 | 常用参数 |
|------|------|----------|
| `design_common.py` | 库模块，不直接运行 | — |
| `dump_interactions.py` | 打印所有 `domId → targetPageId` | `--page <id前缀>`、`--markdown`、`--design <路径>` |
| `validate_interactions.py` | 校验连线合法性 | `--design <路径>`；退出码 `0` 成功，`2` 有错误 |
| `strip_legacy_interactions.py` | 删除废弃 domId（如 `open-code-regex`、`open-code-script-view-test`） | `--dry-run`、`--design <路径>` |
| `apply_canonical_code_interactions.py` | **仅**重写 `page-code-*` 六张卡片的 `interactions` 为规范表 | `--dry-run`、`--design <路径>` |

### 命令示例（仓库根执行）

```bash
# 查看代码相关全部连线
python .claude/skills/design-canvas-format/scripts/dump_interactions.py --page page-code

# 导出为 Markdown 表（便于贴进 interactions.md 附录）
python .claude/skills/design-canvas-format/scripts/dump_interactions.py --markdown > /tmp/interactions-dump.md

# 健康检查
python .claude/skills/design-canvas-format/scripts/validate_interactions.py

# 修复代码区连线（先预览）
python .claude/skills/design-canvas-format/scripts/apply_canonical_code_interactions.py --dry-run
python .claude/skills/design-canvas-format/scripts/apply_canonical_code_interactions.py
```

### `validate_interactions.py` 会检查什么

- `targetPageId` 在 `.design` 的 `data` 里是否存在对应 `page` 卡片  
- 是否仍含 **legacy domId**（`LEGACY_DOM_IDS`，见 `design_common.py`）  
- 是否指向已删除页（如 `page-code-script-test`）  
- 代码 L2 Tab：`open-code-tab-script` 必须 → `page-code-script-library`（不是编辑页）  
- **警告**：`open-script-manage-sheet` 不应出现在 interactions（抽屉仅本地 JS）

### `apply_canonical_code_interactions.py` 覆盖的页面 id

- `page-code-manager`
- `page-code-regex-test`（正则**编辑**页，非独立测试页）
- `page-code-script-library`
- `page-code-script-editor`
- `page-code-memory-prompts`
- `page-code-plugins`

规范内容与 `interactions.md` 第 4 节一致；**不会**修改会话/预设/世界书等其它页面连线。

### 相关文档（画布项目内）

| 文件 | 内容 |
|------|------|
| `chenmumu5-redesign-mobile/interactions.md` | 交互逻辑线、domId 约定、禁止连线清单 |
| `chenmumu5-redesign-mobile/design.md` | 输入框样式、抽屉式二级操作 UI 规范 |
| `chenmumu5-redesign-mobile/partials/` | L2/L3 公用 Tab 条 |

### 注意事项（脚本 + 画布）

- 用户在 **SOLO Design 里保存** 后，可能自动合并/写回旧 `interactions`；保存后务必再跑 `validate_interactions.py`。
- 仅打开抽屉的按钮（如「管理脚本」）在 HTML 中**不要**加 `data-dom-id`。
- 修改 partial 后，需同步所有内联了该 Tab 的 `pages/*.html`（或重新粘贴 partial 内容）。
