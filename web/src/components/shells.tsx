import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
  type KeyboardEventHandler,
  type ReactNode,
  type Ref,
} from 'react'
import { Link, NavLink, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus, initialOf } from '../data'
import { BrandLockup, BrandMark, Button, HudPanel, Icon, Notice } from './ui'
import { SpaceBackdrop } from './space'
import { SkipLink, SkipTarget, useSkipTargetId } from './skip-link'

/* 汉堡/账户下拉的共享可访问性逻辑，实现 WAI-ARIA Disclosure Navigation 模式
   （面板里是导航链接/按钮，不是 role="menu"，因此不用 menu 小部件语义）：
   - 触发器带 aria-expanded / aria-controls / aria-haspopup，useId 保证多实例不重复；
   - 点击面板外部关闭（沿用原 mousedown 行为）；
   - Escape 关闭并把焦点还给触发器按钮；
   - 面板内 ArrowDown/ArrowUp 循环移动焦点，Home/End 跳首尾；
   - 在触发器上按 ArrowDown/ArrowUp 打开面板并把焦点移进首/末项。 */
function useNavDisclosure() {
  const [open, setOpen] = useState(false)
  const panelId = useId()
  const containerRef = useRef<HTMLDivElement>(null)
  const panelRef = useRef<HTMLDivElement>(null)
  const buttonRef = useRef<HTMLButtonElement>(null)
  const pendingFocus = useRef<'first' | 'last' | null>(null)

  const close = useCallback(() => setOpen(false), [])
  const toggle = useCallback(() => setOpen((value) => !value), [])

  const focusableItems = useCallback(() => {
    const panel = panelRef.current
    if (!panel) return []
    return Array.from(panel.querySelectorAll<HTMLElement>('a[href], button:not([disabled])'))
  }, [])

  const moveFocus = useCallback(
    (delta: number) => {
      const items = focusableItems()
      if (items.length === 0) return
      const current = items.indexOf(document.activeElement as HTMLElement)
      const next =
        current === -1 ? (delta > 0 ? 0 : items.length - 1) : (current + delta + items.length) % items.length
      items[next].focus()
    },
    [focusableItems],
  )

  // 点击面板外部关闭
  useEffect(() => {
    if (!open) return
    const onPointer = (event: MouseEvent) => {
      if (!containerRef.current?.contains(event.target as Node)) close()
    }
    document.addEventListener('mousedown', onPointer)
    return () => document.removeEventListener('mousedown', onPointer)
  }, [open, close])

  // Escape 关闭并把焦点还给触发器按钮（焦点在面板内或触发器上都生效）
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        close()
        buttonRef.current?.focus()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, close])

  // 键盘打开（方向键）时，渲染完成后把焦点移进面板首/末项
  useEffect(() => {
    if (!open || pendingFocus.current == null) return
    const items = focusableItems()
    const target = pendingFocus.current === 'first' ? 0 : items.length - 1
    pendingFocus.current = null
    if (items[target]) items[target].focus()
  }, [open, focusableItems])

  const onButtonKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLButtonElement>) => {
      if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
      event.preventDefault()
      if (open) {
        moveFocus(event.key === 'ArrowDown' ? 1 : -1)
      } else {
        pendingFocus.current = event.key === 'ArrowDown' ? 'first' : 'last'
        setOpen(true)
      }
    },
    [open, moveFocus],
  )

  const onPanelKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLDivElement>) => {
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        event.preventDefault()
        moveFocus(event.key === 'ArrowDown' ? 1 : -1)
      } else if (event.key === 'Home' || event.key === 'End') {
        event.preventDefault()
        const items = focusableItems()
        const target = event.key === 'Home' ? 0 : items.length - 1
        if (items[target]) items[target].focus()
      }
    },
    [focusableItems, moveFocus],
  )

  return {
    open,
    panelId,
    containerRef,
    panelRef,
    buttonRef,
    close,
    toggle,
    onButtonKeyDown,
    onPanelKeyDown,
  }
}

/* Expanded at page top, condensed once the user scrolls; sentinel keeps it
   scroll-container agnostic (works for window scroll and inner scrollers). */
function useTopbarExpanded() {
  const [expanded, setExpanded] = useState(true)
  const sentinelRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const sentinel = sentinelRef.current
    if (!sentinel || typeof IntersectionObserver === 'undefined') return
    const observer = new IntersectionObserver(([entry]) => setExpanded(entry.isIntersecting))
    observer.observe(sentinel)
    return () => observer.disconnect()
  }, [])
  return { expanded, sentinelRef }
}

function NavMenu({
  id,
  panelRef,
  onKeyDown,
  extra,
  onNavigate,
}: {
  id: string
  panelRef: Ref<HTMLDivElement>
  onKeyDown: KeyboardEventHandler<HTMLDivElement>
  extra?: ReactNode
  onNavigate?: () => void
}) {
  return (
    <div
      id={id}
      data-menu
      ref={panelRef}
      onKeyDown={onKeyDown}
      className="chenxing-menu absolute right-0 top-full z-[var(--chenxing-z-menu)] mt-3 w-60"
    >
      <Link to="/" className="chenxing-nav-menu-item" onClick={onNavigate}>主页<Icon name="arrow-up-right" size={16} /></Link>
      <Link to="/console" className="chenxing-nav-menu-item" onClick={onNavigate}>控制台<Icon name="layout-dashboard" size={16} /></Link>
      <span className="chenxing-nav-menu-item is-static">
        <span className="flex items-center gap-2">应用广场<span className="chenxing-caption text-[10px] uppercase tracking-[0.08em] text-[var(--chenxing-muted-foreground)]">即将上线</span></span>
        <Icon name="store" size={16} />
      </span>
      <div className="chenxing-divider my-1" />
      <div className="flex items-center justify-between px-3.5 py-2">
        <span className="chenxing-caption text-[11px] tracking-[0.06em]">状态</span>
        <span className="chenxing-caption inline-flex items-center gap-2 text-[11px] tracking-[0.06em] text-[var(--chenxing-success)]">
          <span className="chenxing-status-dot" />星门在线
        </span>
      </div>
      {/* menuExtra 里全是导航性链接/按钮：点任何一项都等于「已作出选择」，
          关掉菜单与跳转同时发生（与 AccountMenu 里菜单项 onClick 关闭的行为一致）。
          包一层 div 让调用方不用感知关闭回调，menuExtra 的 ReactNode 契约保持不变。 */}
      {extra ? <div onClick={onNavigate}>{extra}</div> : null}
    </div>
  )
}

function HamburgerMenu({ extra }: { extra?: ReactNode }) {
  const { open, panelId, containerRef, panelRef, buttonRef, close, toggle, onButtonKeyDown, onPanelKeyDown } =
    useNavDisclosure()
  return (
    <div className="relative" ref={containerRef}>
      <button
        ref={buttonRef}
        type="button"
        className="chenxing-hamburger"
        aria-label="打开导航菜单"
        aria-expanded={open}
        aria-controls={panelId}
        aria-haspopup="true"
        onClick={toggle}
        onKeyDown={onButtonKeyDown}
      >
        <span /><span /><span />
      </button>
      {open ? (
        <NavMenu id={panelId} panelRef={panelRef} onKeyDown={onPanelKeyDown} extra={extra} onNavigate={close} />
      ) : null}
    </div>
  )
}

function AccountMenu() {
  const { open, panelId, containerRef, panelRef, buttonRef, close, toggle, onButtonKeyDown, onPanelKeyDown } =
    useNavDisclosure()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const name = user?.display_name || user?.username || '辰'
  const memberId = user?.id != null ? `NO.${String(user.id).padStart(6, '0')}` : 'NO.000000'
  const handle = user?.username ? `@${user.username}` : '@user'
  return (
    <div className="relative" ref={containerRef}>
      {/* 头像触发器 44x44：WCAG 2.5.8 目标尺寸下限 24，本项目取 40 起步；
          顶栏布局放得下就用 44（与汉堡 40x40 同处一个胶囊，略大一点更易命中） */}
      <button
        ref={buttonRef}
        type="button"
        className="chenxing-avatar h-11 w-11 text-sm"
        aria-label="账户菜单"
        aria-expanded={open}
        aria-controls={panelId}
        aria-haspopup="true"
        onClick={toggle}
        onKeyDown={onButtonKeyDown}
      >
        {initialOf(name)}
      </button>
      {open ? (
        <div id={panelId} ref={panelRef} onKeyDown={onPanelKeyDown} className="chenxing-menu absolute right-0 top-full z-[var(--chenxing-z-menu)] mt-3 w-64 p-0 overflow-hidden">
          {/* ── 用户信息头 ── */}
          <div className="chenxing-account-header">
            <div className="chenxing-avatar h-14 w-14 text-lg pointer-events-none">
              {initialOf(name)}
            </div>
            {/* 用户名是菜单标签而非文档章节标题：用非标题元素承载，类名与视觉不变 */}
            <p className="mt-2 text-sm font-semibold text-[var(--chenxing-foreground)]">{name}</p>
            <div className="mt-2 grid grid-cols-2 gap-x-6 text-center text-[11px]">
              <div>
                <p className="chenxing-caption uppercase tracking-[0.1em]">会员序列</p>
                <p className="chenxing-mono mt-0.5 text-[var(--chenxing-foreground)]">{memberId}</p>
              </div>
              <div>
                <p className="chenxing-caption uppercase tracking-[0.1em]">@ Handle</p>
                <p className="chenxing-mono mt-0.5 text-[var(--chenxing-cyan)]">{handle}</p>
              </div>
            </div>
          </div>
          {/* ── 菜单项 ── */}
          <div className="p-1">
            <Link to="/console/profile" className="chenxing-menu-item" onClick={close}>
              <Icon name="user" className="text-[var(--chenxing-cyan)]" size={16} />账户设置
            </Link>
            <Link to="/console/plans" className="chenxing-menu-item" onClick={close}>
              <Icon name="receipt" className="text-[var(--chenxing-cyan)]" size={16} />套餐订阅
            </Link>
            <span className="chenxing-menu-item is-static">
              <Icon name="book-open" className="text-[var(--chenxing-cyan)]" size={16} />文档中心
              <span className="ml-auto chenxing-caption text-[10px] uppercase tracking-[0.08em] text-[var(--chenxing-muted-foreground)]">即将上线</span>
            </span>
            <div className="chenxing-divider my-1" />
            <button
              type="button"
              className="chenxing-menu-item"
              onClick={() => {
                void logout().then(() => navigate('/login'))
              }}
            >
              <Icon name="log-out" className="text-[var(--chenxing-error)]" size={16} />退出
            </button>
          </div>
        </div>
      ) : null}
    </div>
  )
}


export function GlobalTopbar({
  status,
  action,
  actionTo,
  menuExtra,
  hideBrandWhenExpanded = false,
}: {
  status: string
  action?: string
  actionTo?: string
  menuExtra?: ReactNode
  hideBrandWhenExpanded?: boolean
}) {
  const { expanded, sentinelRef } = useTopbarExpanded()
  const { status: authStatus } = useAuth()
  const loggedIn = authStatus === 'authenticated'
  return (
    <>
      <div ref={sentinelRef} aria-hidden="true" className="chenxing-topbar-sentinel" />
      <header
        className="chenxing-topbar"
        data-expanded={expanded || undefined}
        data-hide-brand-when-expanded={hideBrandWhenExpanded || undefined}
      >
        <Link to="/" className="chenxing-topbar-brand flex items-center gap-2.5 justify-self-start">
          <BrandLockup />
        </Link>
        <div className="chenxing-topbar-status" data-topbar-status>
          <span>{status}</span>
        </div>
        <div className="flex items-center gap-2 justify-self-end">
          <HamburgerMenu extra={menuExtra} />
          {loggedIn ? <AccountMenu /> : action && actionTo ? (
            <Link to={actionTo} className="chenxing-btn-primary text-sm">{action}</Link>
          ) : null}
        </div>
      </header>
    </>
  )
}

export function AuthShell({
  children,
  status,
  action,
  actionTo,
  className = 'chenxing-auth-layout',
  menuExtra,
}: {
  children: ReactNode
  status: string
  action?: string
  actionTo?: string
  className?: string
  menuExtra?: ReactNode
}) {
  /* 跳过链接是 Shell 的第一个可聚焦元素，内容锚点紧跟顶栏之后（见 skip-link.tsx） */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className={className} opacity={0.7}>
      <SkipLink targetId={targetId} />
      <GlobalTopbar status={status} action={action} actionTo={actionTo} menuExtra={menuExtra} />
      <SkipTarget targetId={targetId} />
      {children}
    </SpaceBackdrop>
  )
}

export function AuthPanel({ children, className = 'w-full max-w-md' }: { children: ReactNode; className?: string }) {
  return (
    <section className="relative z-[var(--chenxing-z-content)] flex flex-1 items-center justify-center px-6 py-14 lg:px-12">
      <div className={className}>
        <HudPanel>{children}</HudPanel>
        <p className="chenxing-mono mt-6 text-center text-[10px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]">
          Encrypted Gateway · 天穹辰星
        </p>
      </div>
    </section>
  )
}

/** 控制台导航分组：按角色过滤可见分组，渲染带 active 态的导航项。
    桌面侧栏与移动端汉堡菜单共用同一份数据与 active 判定，避免两处漂移。 */
function ConsoleNavGroups() {
  const { user } = useAuth()
  const location = useLocation()
  const visible = navGroups.filter((group) => group.label === '账户' || group.label === '开发者' || user?.role !== 'user')
  return (
    <>
      {visible.map((group) => (
        <div key={group.label}>
          <p className="chenxing-nav-label">{group.label}</p>
          {group.items.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className="chenxing-nav-item"
              aria-current={location.pathname === item.path ? 'page' : undefined}
            >
              <Icon name={item.icon} size={16} className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </>
  )
}

function Sidebar() {
  return (
    <aside className="chenxing-sidebar flex">
      <Link to="/" className="flex items-center gap-3 px-2">
        <BrandLockup subtitle="用户中心" compact />
      </Link>
      <nav className="chenxing-sidebar-scroll mt-5 no-scrollbar" aria-label="控制台导航">
        <ConsoleNavGroups />
      </nav>
    </aside>
  )
}

/** 移动端核心页快捷栏：固定底栏只承载「账户」组的四项核心页，
    完整导航（开发者/管理/系统）在汉堡菜单里；桌面端由 CSS 隐藏。 */
function BottomNav() {
  const location = useLocation()
  const core = navGroups.find((group) => group.label === '账户')?.items ?? []
  return (
    <nav className="chenxing-bottom-nav" aria-label="控制台快捷导航">
      {core.map((item) => (
        <NavLink
          key={item.path}
          to={item.path}
          className="chenxing-bottom-tab"
          aria-current={location.pathname === item.path ? 'page' : undefined}
        >
          <Icon name={item.icon} size={18} />
          {item.label}
        </NavLink>
      ))}
    </nav>
  )
}

export function ConsoleLayout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const status = pageStatus[location.pathname] || (location.pathname.startsWith('/admin') ? '管理' : '控制台')
  /* 跳过链接盖在最前（侧栏/顶栏之上），内容锚点放在内容列起点，
     这样跳过链接一次 Tab 就能越过侧栏、顶栏与汉堡菜单直达页面内容 */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className="console-shell" opacity={0.4} dense>
      <SkipLink targetId={targetId} />
      <Sidebar />
      <div className="chenxing-console-main relative z-[var(--chenxing-z-content)] flex min-h-screen flex-col">
        {/* sidebar already carries the brand lockup, so the topbar brand only
            appears once the bar condenses into its capsule */}
        <GlobalTopbar
          status={status}
          hideBrandWhenExpanded
          menuExtra={(
            <>
              <div className="chenxing-divider my-1" />
              <ConsoleNavGroups />
            </>
          )}
        />
        <div className="chenxing-console-content flex-1 px-4 py-6 pb-10 sm:px-6 lg:px-8">
          <SkipTarget targetId={targetId} />
          {children}
        </div>
      </div>
      <BottomNav />
    </SpaceBackdrop>
  )
}

export function OAuthShell({ children, footer = true }: { children: ReactNode; footer?: boolean }) {
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop opacity={0.6}>
      <SkipLink targetId={targetId} />
      <section className="oauth-shell">
        <SkipTarget targetId={targetId} />
        {children}
        {footer ? (
          <div className="oauth-footer">
            {/* #240：语言选择与帮助/隐私权/条款均无对应行为，静态文本而非伪控件 */}
            <span className="oauth-footer-label">简体中文</span>
            <div className="oauth-footer-links">
              <span className="oauth-footer-label">帮助</span>
              <span className="oauth-footer-label">隐私权</span>
              <span className="oauth-footer-label">条款</span>
            </div>
          </div>
        ) : null}
      </section>
    </SpaceBackdrop>
  )
}

export function LoadingPanel({ message }: { message: string }) {
  return (
    <HudPanel className="w-full max-w-md">
      <Notice tone="info">{message}</Notice>
    </HudPanel>
  )
}

export function BrandMarkOnly() {
  return <BrandMark />
}
