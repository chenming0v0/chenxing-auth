import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within, waitFor } from '@testing-library/react'
import { ConsoleLayout } from './shells'
import { navGroups } from '../data'
import { setNavigationBlocker } from '../router'

// 可变的桩用户：角色过滤用例需要切换 role。vi.mock 工厂引用 hoisted 对象，
// 测试间直接改属性即可，不必为每个用例重新 mock 整个模块。
const { mockUser } = vi.hoisted(() => ({
  mockUser: { id: 1, username: 'chenxing', display_name: '测试员', role: 'admin' },
}))

// ConsoleLayout 依赖 useAuth；mock 掉 auth-state，避免 AuthProvider 挂载时
// 额外发出 /auth/me 请求。
vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: mockUser,
    status: 'authenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    clear: () => {},
    logout: vi.fn().mockResolvedValue({ revoked: true }),
  }),
}))

const allItems = navGroups.flatMap((group) => group.items)
const adminItems = allItems.filter((item) => !item.ownerOnly)
const groupPaths = (label: string, role = 'admin') => (navGroups.find((group) => group.label === label)?.items ?? [])
  .filter((item) => !item.ownerOnly || role === 'owner')
  .map((item) => item.path)

beforeEach(() => {
  // useLocation 在渲染时读取 window.location.pathname
  window.history.replaceState({}, '', '/console')
  mockUser.role = 'admin'
})

afterEach(() => {
  setNavigationBlocker(null)
  cleanup()
  vi.restoreAllMocks()
})

function renderConsole() {
  render(
    <ConsoleLayout>
      <div>页面内容</div>
    </ConsoleLayout>,
  )
}

/** 打开汉堡菜单并返回菜单容器；断言菜单确实弹出。 */
function openHamburgerMenu(): HTMLElement {
  renderConsole()
  fireEvent.click(screen.getByRole('button', { name: '打开导航菜单' }))
  const menu = document.querySelector('.cx-nav-panel') as HTMLElement
  expect(menu).toBeTruthy()
  return menu
}

/** 打开移动端底栏的「全部」区域面板并返回面板容器。
    先聚焦触发器再点击：真实指针点击会先把焦点交给按钮，
    useModalFocus 正是依赖这个焦点来源在关闭时归还焦点。 */
function openNavSheet(): HTMLElement {
  const trigger = screen.getByRole('button', { name: '全部' })
  trigger.focus()
  fireEvent.click(trigger)
  const sheet = screen.getByRole('dialog', { name: '全部页面' })
  expect(sheet).toBeTruthy()
  return sheet
}

const sidebar = () => within(screen.getByRole('navigation', { name: '控制台导航' }))
const bottomNav = () => within(screen.getByRole('navigation', { name: '当前区域导航' }))
const hrefsIn = (scope: ReturnType<typeof within>) => scope
  .getAllByRole('link')
  .map((link: HTMLElement) => link.getAttribute('href'))

/** 换到另一个路径/角色重新挂载控制台（同一用例内切换区域时用）。 */
function remountAt(path: string, role = 'admin') {
  cleanup()
  window.history.replaceState({}, '', path)
  mockUser.role = role
  renderConsole()
}

describe('ConsoleLayout 移动端导航可达性（#197）', () => {
  it('桌面侧栏按角色渲染可见导航项、带正确 href 并标记 active 态', () => {
    renderConsole()
    for (const item of adminItems) {
      expect(sidebar().getByRole('link', { name: item.label }).getAttribute('href')).toBe(item.path)
    }
    for (const item of allItems.filter((candidate) => candidate.ownerOnly)) {
      expect(sidebar().queryByRole('link', { name: item.label })).toBeNull()
    }
    expect(sidebar().getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
    expect(sidebar().getByRole('link', { name: '套餐与权益' }).getAttribute('aria-current')).toBeNull()

    // Owner 才看到 ownerOnly 的系统入口
    remountAt('/console', 'owner')
    for (const item of allItems.filter((candidate) => candidate.ownerOnly)) {
      expect(sidebar().getByRole('link', { name: item.label }).getAttribute('href')).toBe(item.path)
    }

    // 普通用户没有管理/系统分组
    remountAt('/console', 'user')
    expect(sidebar().queryByRole('link', { name: '仪表盘' })).toBeNull()
    expect(sidebar().queryByRole('link', { name: '系统设置' })).toBeNull()
    expect(sidebar().getByRole('link', { name: '接入应用' })).toBeTruthy()
  })

  it('汉堡菜单只保留区域级入口：开发者/管理不再平铺分组', () => {
    const menu = openHamburgerMenu()
    expect(within(menu).getByRole('link', { name: '控制台' }).getAttribute('href')).toBe('/console')
    // 开发者入口默认落在「接入应用」，管理入口默认落在「仪表盘」
    expect(within(menu).getByRole('link', { name: '开发者' }).getAttribute('href')).toBe('/console/integrate')
    expect(within(menu).getByRole('link', { name: '管理' }).getAttribute('href')).toBe('/admin')
    for (const flattened of ['总览', '钱包', '接入应用', '套餐与权益', '仪表盘', '用户管理', '套餐管理', '邀请码', '身份提供商', '系统设置']) {
      expect(within(menu).queryByRole('link', { name: flattened })).toBeNull()
    }
    // 分组列表已整体移出汉堡菜单，不再渲染 extra 容器
    expect(menu.querySelector('.cx-nav-panel-extra')).toBeNull()

    // 普通用户没有管理入口
    cleanup()
    mockUser.role = 'user'
    const plain = openHamburgerMenu()
    expect(within(plain).queryByRole('link', { name: '管理' })).toBeNull()
    expect(within(plain).getByRole('link', { name: '开发者' })).toBeTruthy()
  })

  it('点击汉堡菜单里的导航项后菜单关闭', async () => {
    const menu = openHamburgerMenu()
    fireEvent.click(within(menu).getByRole('link', { name: '开发者' }))
    // 关闭带 300ms 退出动画（遮罩淡出 + 面板收拢），卸载发生在动画结束后
    await waitFor(() => expect(document.querySelector('.cx-nav-panel')).toBeNull())
  })

  it('移动端底栏承载当前区域的全部页面，不再按白名单裁剪（#693）', () => {
    // 账户区：钱包曾被白名单裁掉
    renderConsole()
    expect(hrefsIn(bottomNav())).toEqual(groupPaths('账户'))
    expect(bottomNav().getByRole('link', { name: '钱包' })).toBeTruthy()
    expect(bottomNav().getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
    // 底栏只承载当前分组，跨区域切换走「全部」面板，分组语义不被压平
    expect(bottomNav().queryByRole('link', { name: '接入应用' })).toBeNull()

    remountAt('/console/integrate')
    expect(hrefsIn(bottomNav())).toEqual(groupPaths('开发者'))
    expect(bottomNav().getByRole('link', { name: '接入应用' }).getAttribute('aria-current')).toBe('page')
    expect(bottomNav().queryByRole('link', { name: '总览' })).toBeNull()

    // 管理区：Client 管理、审计日志、邀请码曾被白名单裁掉；admin 看不到 ownerOnly 的套餐管理
    remountAt('/admin/users')
    expect(hrefsIn(bottomNav())).toEqual(['/admin', '/admin/users', '/admin/clients', '/admin/audit', '/admin/invitations'])
    expect(bottomNav().getByRole('link', { name: '用户管理' }).getAttribute('aria-current')).toBe('page')
  })

  it('系统分组自成一区，Owner 的底栏按分组补齐 ownerOnly 页面（#693）', () => {
    remountAt('/admin/plans', 'owner')
    expect(hrefsIn(bottomNav())).toEqual(groupPaths('管理', 'owner'))

    remountAt('/admin/oauth-providers', 'owner')
    expect(hrefsIn(bottomNav())).toEqual(['/admin/oauth-providers', '/admin/settings'])
    expect(bottomNav().getByRole('link', { name: '身份提供商' }).getAttribute('aria-current')).toBe('page')
  })
})

describe('移动端「全部」区域面板承载完整导航（#693）', () => {
  it('面板按分组标题列出当前角色可见的每一个页面，并标记 active 态', () => {
    window.history.replaceState({}, '', '/console/wallet')
    renderConsole()
    const sheet = openNavSheet()
    // 玻璃容器来自组件库 HudPanel，不自建玻璃卡片样式
    expect(sheet.className).toContain('chenxing-hud-panel')
    expect(sheet.className).not.toContain('chenxing-glass-strong')
    expect(sheet.className).not.toContain('chenxing-hud-frame')
    // 分组标题保留，账户/开发者/管理不被压平成一排 tab
    for (const label of ['账户', '开发者', '管理']) expect(within(sheet).getByText(label)).toBeTruthy()
    // 回归 Issue 点名的钱包、Client 管理、审计日志、邀请码都在面板里；ownerOnly 页面对 admin 隐藏
    expect(hrefsIn(within(sheet))).toEqual(adminItems.map((item) => item.path))
    expect(within(sheet).getByRole('link', { name: '钱包' }).getAttribute('aria-current')).toBe('page')
    expect(within(sheet).getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBeNull()
  })

  it('面板按角色增减分组：Owner 补齐系统分组，普通用户没有管理/系统', () => {
    remountAt('/console', 'owner')
    const owner = openNavSheet()
    expect(within(owner).getByText('系统')).toBeTruthy()
    expect(hrefsIn(within(owner))).toEqual(allItems.map((item) => item.path))

    remountAt('/console', 'user')
    const plain = openNavSheet()
    expect(within(plain).queryByText('管理')).toBeNull()
    expect(within(plain).queryByText('系统')).toBeNull()
    expect(hrefsIn(within(plain))).toEqual([...groupPaths('账户'), ...groupPaths('开发者')])
  })

  it('触发按钮声明 dialog 展开态；点击页面项、Escape、遮罩都关闭面板', () => {
    renderConsole()
    const trigger = screen.getByRole('button', { name: '全部' })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
    expect(trigger.getAttribute('aria-haspopup')).toBe('dialog')
    const sheet = openNavSheet()
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
    expect(sheet.id).toBe(trigger.getAttribute('aria-controls'))

    // 点击当前页也要关闭：路径不变，不能只靠路径变化收起面板
    fireEvent.click(within(sheet).getByRole('link', { name: '总览' }))
    expect(screen.queryByRole('dialog', { name: '全部页面' })).toBeNull()
    expect(window.location.pathname).toBe('/console')

    openNavSheet()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog', { name: '全部页面' })).toBeNull()
    expect(document.activeElement).toBe(trigger)

    openNavSheet()
    fireEvent.click(document.querySelector('.cx-nav-sheet-overlay') as HTMLElement)
    expect(screen.queryByRole('dialog', { name: '全部页面' })).toBeNull()
  })
})
