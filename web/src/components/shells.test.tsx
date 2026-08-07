import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within } from '@testing-library/react'
import { ConsoleLayout } from './shells'
import { navGroups } from '../data'

// 可变的桩用户：角色过滤用例需要切换 role。vi.mock 工厂引用 hoisted 对象，
// 测试间直接改属性即可，不必为每个用例重新 mock 整个模块。
const { mockUser } = vi.hoisted(() => ({
  mockUser: { id: 1, username: 'chenxing', display_name: '测试员', role: 'admin' },
}))

// ConsoleLayout 依赖 useAuth；mock 掉 auth-state，避免 AuthProvider 挂载时
// 额外发出 /auth/me 与 /admin/bootstrap/status 请求。
// 工厂在模块首次导入时执行，只能引用 hoisted 变量，不能引用文件顶层 const。
vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: mockUser,
    status: 'authenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    refreshBootstrap: () => Promise.resolve('ready'),
    clear: () => {},
    logout: () => Promise.resolve(),
  }),
}))

const allItems = navGroups.flatMap((group) => group.items)
const coreItems = navGroups.find((group) => group.label === '账户')?.items ?? []

beforeEach(() => {
  // useLocation 在渲染时读取 window.location.pathname
  window.history.replaceState({}, '', '/console')
  mockUser.role = 'admin'
})

afterEach(cleanup)

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
  const menu = document.querySelector('[data-menu]') as HTMLElement
  expect(menu).toBeTruthy()
  return menu
}

describe('ConsoleLayout 移动端导航可达性（#197）', () => {
  it('桌面侧栏仍渲染全部可见导航项并带正确 href', () => {
    renderConsole()
    const sidebar = screen.getByRole('navigation', { name: '控制台导航' })
    for (const item of allItems) {
      expect(within(sidebar).getByRole('link', { name: item.label }).getAttribute('href')).toBe(item.path)
    }
  })

  it('侧栏按当前路径标记 active 态', () => {
    renderConsole()
    const sidebar = screen.getByRole('navigation', { name: '控制台导航' })
    expect(within(sidebar).getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
    expect(within(sidebar).getByRole('link', { name: '套餐与权益' }).getAttribute('aria-current')).toBeNull()
  })

  it('汉堡菜单里包含完整控制台导航，核心页全部可达', () => {
    const menu = openHamburgerMenu()
    for (const item of allItems) {
      expect(within(menu).getByRole('link', { name: item.label }).getAttribute('href')).toBe(item.path)
    }
  })

  it('汉堡菜单里的导航项与侧栏一样标记当前页', () => {
    const menu = openHamburgerMenu()
    expect(within(menu).getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
  })

  it('移动端底栏只承载核心页，且标记当前页', () => {
    renderConsole()
    const bottom = screen.getByRole('navigation', { name: '控制台快捷导航' })
    const hrefs = within(bottom).getAllByRole('link').map((link) => link.getAttribute('href'))
    expect(hrefs).toEqual(coreItems.map((item) => item.path))
    expect(within(bottom).getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
    // 开发者/管理页不在底栏，属于汉堡菜单
    expect(within(bottom).queryByRole('link', { name: '接入应用' })).toBeNull()
  })

  it('点击汉堡菜单里的导航项后菜单关闭', () => {
    const menu = openHamburgerMenu()
    fireEvent.click(within(menu).getByRole('link', { name: '套餐与权益' }))
    expect(document.querySelector('[data-menu]')).toBeNull()
  })

  it('普通用户看不到管理/系统分组', () => {
    mockUser.role = 'user'
    renderConsole()
    const sidebar = screen.getByRole('navigation', { name: '控制台导航' })
    expect(within(sidebar).queryByRole('link', { name: '仪表盘' })).toBeNull()
    expect(within(sidebar).queryByRole('link', { name: '系统设置' })).toBeNull()
    expect(within(sidebar).getByRole('link', { name: '接入应用' })).toBeTruthy()
  })
})

describe('汉堡/账户菜单 Disclosure 可访问性（#220）', () => {
  /** 面板里的可聚焦项（与 useNavDisclosure 的 focusableItems 同一选择器）。 */
  function menuItems(menu: HTMLElement): HTMLElement[] {
    return Array.from(menu.querySelectorAll<HTMLElement>('a[href], button:not([disabled])'))
  }

  it('汉堡按钮带 aria-expanded/aria-controls/aria-haspopup，面板挂在 aria-controls 指向的 id 上', () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    expect(button.getAttribute('aria-expanded')).toBe('false')
    expect(button.getAttribute('aria-haspopup')).toBe('true')
    const panelId = button.getAttribute('aria-controls')
    expect(panelId).toBeTruthy()
    fireEvent.click(button)
    expect(button.getAttribute('aria-expanded')).toBe('true')
    const menu = document.querySelector('[data-menu]') as HTMLElement
    expect(menu.id).toBe(panelId)
  })

  it('汉堡与账户两个触发器的 aria-controls id 互不重复', () => {
    renderConsole()
    const hamburgerId = screen.getByRole('button', { name: '打开导航菜单' }).getAttribute('aria-controls')
    const accountId = screen.getByRole('button', { name: '账户菜单' }).getAttribute('aria-controls')
    expect(hamburgerId).toBeTruthy()
    expect(accountId).toBeTruthy()
    expect(hamburgerId).not.toBe(accountId)
  })

  it('Escape 关闭汉堡菜单并把焦点还给触发器按钮', () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    fireEvent.click(button)
    expect(document.querySelector('[data-menu]')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(document.querySelector('[data-menu]')).toBeNull()
    expect(document.activeElement).toBe(button)
  })

  it('Escape 关闭账户菜单并把焦点还给头像按钮', () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '账户菜单' })
    fireEvent.click(button)
    const panelId = button.getAttribute('aria-controls') as string
    expect(document.getElementById(panelId)).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(document.getElementById(panelId)).toBeNull()
    expect(document.activeElement).toBe(button)
  })

  it('在汉堡按钮上按 ArrowDown 打开菜单并聚焦首项', () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    fireEvent.keyDown(button, { key: 'ArrowDown' })
    const menu = document.querySelector('[data-menu]') as HTMLElement
    expect(menu).toBeTruthy()
    expect(document.activeElement).toBe(menuItems(menu)[0])
  })

  it('面板内 ArrowDown/ArrowUp 在可聚焦项间循环移动焦点', () => {
    const menu = openHamburgerMenu()
    const items = menuItems(menu)
    expect(items.length).toBeGreaterThan(1)
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    // 从触发器用方向键进入面板
    fireEvent.keyDown(button, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[0])
    // 顺移
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[1])
    // 回退
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowUp' })
    expect(document.activeElement).toBe(items[0])
    // 首项 ArrowUp 回绕到末项
    fireEvent.keyDown(items[0], { key: 'ArrowUp' })
    expect(document.activeElement).toBe(items[items.length - 1])
    // 末项 ArrowDown 回绕到首项
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[0])
  })

  it('面板内 Home/End 跳到首尾项', () => {
    const menu = openHamburgerMenu()
    const items = menuItems(menu)
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    fireEvent.keyDown(button, { key: 'ArrowDown' })
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'ArrowDown' })
    expect(document.activeElement).toBe(items[1])
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'Home' })
    expect(document.activeElement).toBe(items[0])
    fireEvent.keyDown(document.activeElement as HTMLElement, { key: 'End' })
    expect(document.activeElement).toBe(items[items.length - 1])
  })

  it('点击导航项后菜单关闭（原有行为不变）', () => {
    const menu = openHamburgerMenu()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    expect(button.getAttribute('aria-expanded')).toBe('true')
    fireEvent.click(within(menu).getByRole('link', { name: '套餐与权益' }))
    expect(document.querySelector('[data-menu]')).toBeNull()
    expect(button.getAttribute('aria-expanded')).toBe('false')
  })
})
