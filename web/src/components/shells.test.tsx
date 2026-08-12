import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, within, waitFor } from '@testing-library/react'
import { AuthShell, ConsoleLayout, OAuthShell } from './shells'
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

  it('汉堡菜单只保留区域级入口：开发者/管理不再平铺分组', () => {
    const menu = openHamburgerMenu()
    expect(within(menu).getByRole('link', { name: '控制台' }).getAttribute('href')).toBe('/console')
    // 开发者入口默认落在「接入应用」，管理入口默认落在「仪表盘」
    expect(within(menu).getByRole('link', { name: '开发者' }).getAttribute('href')).toBe('/console/integrate')
    expect(within(menu).getByRole('link', { name: '管理' }).getAttribute('href')).toBe('/admin')
    for (const flattened of ['总览', '接入应用', '套餐与权益', '仪表盘', '用户管理', '套餐管理', '系统设置']) {
      expect(within(menu).queryByRole('link', { name: flattened })).toBeNull()
    }
    // 分组列表已整体移出汉堡菜单，不再渲染 extra 容器
    expect(menu.querySelector('.cx-nav-panel-extra')).toBeNull()
  })

  it('普通用户的汉堡菜单没有管理入口', () => {
    mockUser.role = 'user'
    const menu = openHamburgerMenu()
    expect(within(menu).queryByRole('link', { name: '管理' })).toBeNull()
    expect(within(menu).getByRole('link', { name: '开发者' })).toBeTruthy()
  })

  it('移动端底栏只承载核心页，且标记当前页', () => {
    renderConsole()
    const bottom = screen.getByRole('navigation', { name: '控制台快捷导航' })
    const hrefs = within(bottom).getAllByRole('link').map((link) => link.getAttribute('href'))
    expect(hrefs).toEqual(coreItems.map((item) => item.path))
    expect(within(bottom).getByRole('link', { name: '总览' }).getAttribute('aria-current')).toBe('page')
    // 开发者/管理页不在账户区底栏
    expect(within(bottom).queryByRole('link', { name: '接入应用' })).toBeNull()
    expect(within(bottom).queryByRole('link', { name: '套餐与权益' })).toBeNull()
  })

  it('开发者区底栏切换为接入应用/授权测试/套餐与权益', () => {
    window.history.replaceState({}, '', '/console/integrate')
    renderConsole()
    const bottom = screen.getByRole('navigation', { name: '控制台快捷导航' })
    const hrefs = within(bottom).getAllByRole('link').map((link) => link.getAttribute('href'))
    expect(hrefs).toEqual(['/console/integrate', '/console/playground', '/console/plans'])
    expect(within(bottom).getByRole('link', { name: '接入应用' }).getAttribute('aria-current')).toBe('page')
    expect(within(bottom).queryByRole('link', { name: '总览' })).toBeNull()
  })

  it('管理区底栏切换为仪表盘/用户管理/套餐管理/系统设置', () => {
    window.history.replaceState({}, '', '/admin/users')
    renderConsole()
    const bottom = screen.getByRole('navigation', { name: '控制台快捷导航' })
    const hrefs = within(bottom).getAllByRole('link').map((link) => link.getAttribute('href'))
    expect(hrefs).toEqual(['/admin', '/admin/users', '/admin/plans', '/admin/settings'])
    expect(within(bottom).getByRole('link', { name: '用户管理' }).getAttribute('aria-current')).toBe('page')
    expect(within(bottom).queryByRole('link', { name: '总览' })).toBeNull()
  })

  it('点击汉堡菜单里的导航项后菜单关闭', async () => {
    const menu = openHamburgerMenu()
    fireEvent.click(within(menu).getByRole('link', { name: '开发者' }))
    // 关闭带 300ms 退出动画（遮罩淡出 + 面板收拢），卸载发生在动画结束后
    await waitFor(() => expect(document.querySelector('[data-menu]')).toBeNull())
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

  it('Escape 关闭汉堡菜单并把焦点还给触发器按钮', async () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    fireEvent.click(button)
    expect(document.querySelector('[data-menu]')).toBeTruthy()
    fireEvent.keyDown(document, { key: 'Escape' })
    // 关闭带 300ms 退出动画，卸载发生在动画结束后
    await waitFor(() => expect(document.querySelector('[data-menu]')).toBeNull())
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

  it('点击导航项后菜单关闭（原有行为不变）', async () => {
    const menu = openHamburgerMenu()
    const button = screen.getByRole('button', { name: '打开导航菜单' })
    expect(button.getAttribute('aria-expanded')).toBe('true')
    fireEvent.click(within(menu).getByRole('link', { name: '开发者' }))
    // 关闭带 300ms 退出动画，卸载发生在动画结束后
    await waitFor(() => expect(document.querySelector('[data-menu]')).toBeNull())
    expect(button.getAttribute('aria-expanded')).toBe('false')
  })
})

describe('账户菜单用户信息不做成文档标题（#226）', () => {
  it('账户菜单里用户名为非标题标签，菜单整体不含任何 heading', () => {
    renderConsole()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const panelId = screen.getByRole('button', { name: '账户菜单' }).getAttribute('aria-controls') as string
    const panel = document.getElementById(panelId) as HTMLElement
    expect(panel).toBeTruthy()
    expect(within(panel).queryByRole('heading')).toBeNull()
    // 用户名仍在原位置以原样式渲染，只是语义从 h3 变成普通文本标签
    const nameLabel = within(panel).getByText('测试员')
    expect(nameLabel.tagName).toBe('P')
    expect(nameLabel.className).toContain('text-base font-semibold')
  })
})

describe('账户菜单头像触发器目标尺寸（WCAG 2.5.8, #229）', () => {
  it('头像触发器至少 40x40，布局允许时取 44（h-11 w-11）', () => {
    renderConsole()
    const button = screen.getByRole('button', { name: '账户菜单' })
    // jsdom 不做布局，断言尺寸类；h-11 w-11 = 44px，若回退到 h-9 w-9（36px）即不达标
    expect(button.className).toContain('h-11')
    expect(button.className).toContain('w-11')
  })
})

describe('全局「跳到主内容」跳过链接（#225）', () => {
  /** 断言 Shell 的跳过链接与内容锚点成对出现且互相对应。 */
  function assertSkipPair(container: HTMLElement) {
    const skip = within(container).getByRole('link', { name: /跳到主内容/ })
    expect(skip.className).toContain('chenxing-skip-link')
    const targetId = skip.getAttribute('href')!.replace(/^#/, '')
    expect(targetId).toBeTruthy()
    const target = container.querySelector(`#${targetId}`) as HTMLElement
    expect(target).toBeTruthy()
    expect(target.className).toContain('chenxing-skip-target')
    expect(target.getAttribute('tabindex')).toBe('-1')
    return { skip, target }
  }

  it('ConsoleLayout：跳过链接是第一个链接，锚点在侧栏/顶栏之后、内容之前', () => {
    const { container } = render(
      <ConsoleLayout>
        <div>页面内容</div>
      </ConsoleLayout>,
    )
    const { skip, target } = assertSkipPair(container)
    // 跳过链接必须是页面上第一个可聚焦的链接（先于侧栏品牌与导航）
    const links = within(container).getAllByRole('link')
    expect(links[0]).toBe(skip)
    // 锚点按 DOM 顺序位于侧栏之后（跳过链接位于侧栏之前）
    const sidebar = within(container).getByRole('navigation', { name: '控制台导航' })
    expect(skip.compareDocumentPosition(sidebar) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(sidebar.compareDocumentPosition(target) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    // 锚点落在内容列里、页面内容之前
    const content = container.querySelector('.chenxing-console-content') as HTMLElement
    expect(content.contains(target)).toBe(true)
    expect(target.nextElementSibling?.textContent).toBe('页面内容')
  })

  it('AuthShell 与 OAuthShell 同样渲染成对的跳过链接与锚点', () => {
    const auth = render(<AuthShell status="认证中枢"><div>登录内容</div></AuthShell>)
    assertSkipPair(auth.container)
    const oauth = render(<OAuthShell><div>授权内容</div></OAuthShell>)
    assertSkipPair(oauth.container)
  })

  it('同一页面挂载多个 Shell 时，锚点 id 不重复且各指各的', () => {
    const first = render(<ConsoleLayout><div>甲</div></ConsoleLayout>)
    const second = render(<ConsoleLayout><div>乙</div></ConsoleLayout>)
    const ids = [first, second].map(({ container }) =>
      within(container).getByRole('link', { name: /跳到主内容/ }).getAttribute('href')!.replace(/^#/, ''),
    )
    expect(ids[0]).not.toBe(ids[1])
    expect(document.getElementById(ids[0])).toBe(first.container.querySelector('.chenxing-skip-target'))
    expect(document.getElementById(ids[1])).toBe(second.container.querySelector('.chenxing-skip-target'))
  })

  it('跳过链接是原生锚点，点击不改写路由路径', () => {
    const { container } = render(
      <ConsoleLayout>
        <div>页面内容</div>
      </ConsoleLayout>,
    )
    const skip = within(container).getByRole('link', { name: /跳到主内容/ })
    fireEvent.click(skip)
    expect(window.location.pathname).toBe('/console')
  })
})

describe('无行为控件改为静态文本（#240）', () => {
  it('OAuth 页脚语言选择器不再是带 aria-haspopup 的按钮，帮助/隐私权/条款不再是伪链接', () => {
    const { container } = render(<OAuthShell><div>授权内容</div></OAuthShell>)
    const footer = container.querySelector('.oauth-footer') as HTMLElement
    expect(footer).toBeTruthy()
    // 语言选择器不声明 listbox，也不渲染成按钮/combobox
    expect(within(footer).queryByRole('button', { name: /简体中文/ })).toBeNull()
    expect(within(footer).queryByRole('combobox')).toBeNull()
    expect(footer.querySelector('[aria-haspopup]')).toBeNull()
    // 语言与页脚链接保留为静态文本，维持页脚视觉平衡
    for (const label of ['简体中文', '帮助', '隐私权', '条款']) {
      const el = within(footer).getByText(label)
      expect(el.tagName).toBe('SPAN')
      expect(el.getAttribute('href')).toBeNull()
    }
    // 页脚不存在任何 href="#" 的死链接
    expect(footer.querySelectorAll('a[href="#"]')).toHaveLength(0)
  })

  it('账户菜单「文档中心」与汉堡菜单「应用广场」不再是按钮', () => {
    renderConsole()
    fireEvent.click(screen.getByRole('button', { name: '账户菜单' }))
    const panelId = screen.getByRole('button', { name: '账户菜单' }).getAttribute('aria-controls') as string
    const accountPanel = document.getElementById(panelId) as HTMLElement
    expect(accountPanel).toBeTruthy()
    expect(within(accountPanel).queryByRole('button', { name: /文档中心/ })).toBeNull()
    expect(within(accountPanel).getByText('文档中心').tagName).toBe('SPAN')

    fireEvent.click(screen.getByRole('button', { name: '打开导航菜单' }))
    const menu = document.querySelector('[data-menu]') as HTMLElement
    expect(menu).toBeTruthy()
    expect(within(menu).queryByRole('button', { name: /应用广场/ })).toBeNull()
    expect(within(menu).getByText('应用广场').tagName).toBe('SPAN')
  })
})
