# Personal Profile Account Management Implementation Plan

**Goal:** 在个人信息页内完成 New API 风格的可扩展账户绑定、安全设置、Passkey 和 TOTP 管理，不新增独立页面。

**Architecture:** `ConsoleProfile` 负责用户摘要、资料/密码表单和活跃会话；`AccountManagement` 负责双 Tab 与认证因子编排；`ExternalIdentities` 和 `SecuritySettings` 分别负责两个 Tab 的内容。旧安全路径仅兼容渲染 `ConsoleProfile`。

**Tech Stack:** React 19, TypeScript, Tailwind CSS 4, Vitest, Testing Library, Lucide, qrcode.

### Task 1: 可扩展账户绑定

- [x] 合并公共 provider 与已绑定 identity，并保留失效 provider 的已绑定记录。
- [x] 内建邮箱主身份，常见 provider 图标映射，未知 provider 通用回退。
- [x] 保留绑定、解除、密码重新认证、CSRF、加载和错误状态。

### Task 2: 安全设置

- [x] 建立可访问的“账户绑定 / 安全设置”双 Tab。
- [x] 将显示名称和用户名移入“账户资料”HUD 弹窗，并把邮箱拆为同级的独立条目与 HUD 弹窗。
- [x] 将密码修改表单改为当前行展开。
- [x] 保留 Passkey 注册/追加、因子移除和 TOTP 二维码确认流程。

### Task 3: 并入个人信息页

- [x] 删除“基本资料”卡片，在用户摘要后渲染全宽账户管理面板。
- [x] 移除侧栏与账户菜单的独立“账户与安全”入口。
- [x] 让 `/console/security` 与 `/settings/security` 兼容渲染个人信息页。
- [x] 拆分 `AuthorizedApps`，避免个人信息模块继续膨胀。

### Task 4: 后端跟踪

- [x] 创建 TOTP 真实联调 Issue #555。
- [x] 创建 Passkey 真实联调 Issue #556。
- [x] 创建可扩展外部账户绑定 Issue #557。
- [x] 创建用户名修改后端契约 Issue #558。
- [x] 创建邮箱修改与双阶段验证后端契约 Issue #559。

### Task 5: 验证与打包

- [x] TDD 覆盖个人页布局迁移，并观察测试先失败再通过。
- [x] 完成桌面与 375px 浏览器验收，检查无横向溢出。
- [x] 运行完整 Vitest、Vite 构建和 `src-line-limit` 最终验证。
- [x] 检查最终 diff、生成产物与需求清单。
