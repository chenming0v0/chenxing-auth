import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent as ReactKeyboardEvent,
  type KeyboardEventHandler,
  type ReactNode,
  type Ref,
} from 'react'
import { Link, NavLink, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus } from '../data'
import { avatarUrl, getEntitlements, type EntitlementItem } from '../api'
import { AvatarContent, BrandLockup, BrandMark, Button, HudPanel, Icon, Notice } from './ui'
import { ScrambleText } from './motion'
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

  // 点击面板外部关闭。汉堡导航的遮罩/面板挂在顶栏之外（见 GlobalTopbar 注释：
  // 遮罩必须是顶栏的兄弟节点），已不在 containerRef 子树里，故面板也算"内部"。
  useEffect(() => {
    if (!open) return
    const onPointer = (event: MouseEvent) => {
      const target = event.target as Node
      if (!containerRef.current?.contains(target) && !panelRef.current?.contains(target)) close()
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

function NavMenu({ id, panelRef, onKeyDown, extra, onNavigate }: {
  id: string
  panelRef: Ref<HTMLDivElement>
  onKeyDown: KeyboardEventHandler<HTMLDivElement>
  extra?: ReactNode
  onNavigate?: () => void
}) {
  /* 管理入口只对已登录的管理角色显示；未登录时 user 为 null，必须显式排除 */
  const { user } = useAuth()
  const showAdmin = user != null && user.role !== 'user'
  return (
    <div id={id} data-menu ref={panelRef} onKeyDown={onKeyDown} className="chenxing-menu cx-nav-panel"
      onClick={(event) => event.stopPropagation()}>
      <Link to="/" className="cx-nav-row" style={{ '--i': 0 } as CSSProperties} onClick={onNavigate}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">主页</span></span>
        <Icon name="arrow-up-right" size={16} />
      </Link>
      <Link to="/console" className="cx-nav-row" style={{ '--i': 1 } as CSSProperties} onClick={onNavigate}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">控制台</span></span>
        <Icon name="layout-dashboard" size={16} />
      </Link>
      {/* 开发者入口默认落在「接入应用」：开发者分组的第一页 */}
      <Link to="/console/integrate" className="cx-nav-row" style={{ '--i': 2 } as CSSProperties} onClick={onNavigate}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">开发者</span></span>
        <Icon name="code-2" size={16} />
      </Link>
      {/* 管理入口默认落在「仪表盘」：管理分组的第一页，具体页面切换交给管理区底栏 */}
      {showAdmin ? (
        <Link to="/admin" className="cx-nav-row" style={{ '--i': 3 } as CSSProperties} onClick={onNavigate}>
          <span className="cx-nav-row-label"><span className="cx-nav-row-text">管理</span></span>
          <Icon name="gauge" size={16} />
        </Link>
      ) : null}
      <span className="cx-nav-row is-static" style={{ '--i': showAdmin ? 4 : 3 } as CSSProperties}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">应用广场</span>
          <span className="chenxing-caption ml-2 self-center text-[10px] uppercase tracking-[0.08em] text-[var(--chenxing-muted-foreground)]">即将上线</span>
        </span>
        <Icon name="store" size={16} />
      </span>
      {/* menuExtra 里全是导航性链接/按钮：点击即视为已作选择，关闭与跳转同时发生；
          包一层 div 让调用方不用感知关闭回调，ReactNode 契约不变。 */}
      {extra ? <div className="cx-nav-panel-extra" onClick={onNavigate}>{extra}</div> : null}
    </div>
  )
}

/* 关闭时保留退出动画窗口（遮罩淡出 + 面板收拢，时长由调用方按 CSS 过渡传入）
   再卸载。closing 在渲染期派生（React 认可的 derived-state 写法）：打开的那一
   拍面板立即挂载——useNavDisclosure 的键盘焦点转移依赖同一拍里 panelRef 已就位。 */
function useExitDelay(open: boolean, ms: number) {
  const [closing, setClosing] = useState(false)
  const prevOpen = useRef(open)
  if (prevOpen.current !== open) {
    prevOpen.current = open
    if (!open) setClosing(true)
  }
  useEffect(() => {
    if (!closing) return
    const timer = window.setTimeout(() => setClosing(false), ms)
    return () => window.clearTimeout(timer)
  }, [closing, ms])
  return closing
}

/* 手风琴展开高度：lamalama 的菜单是 GSAP `height: 0 → auto`（expo.out 0.45s）。
   CSS 过渡不认 auto，所以测出内容真实高度再过渡到该像素值。内容高度不是常量
   （控制台菜单按角色增减分组、视口旋转会改变可用高度），因此用 ResizeObserver
   加 resize 监听持续重测，而不是展开时测一次就写死。
   上限取 70vh：菜单长于视口时容器封顶、内部滚动，胶囊不会顶穿屏幕。 */
const DRAWER_MAX_VH = 0.7

function useAccordionHeight(open: boolean) {
  const innerRef = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState(0)
  useEffect(() => {
    const inner = innerRef.current
    if (!open || !inner) {
      setHeight(0)
      return
    }
    const measure = () => {
      const limit = typeof window === 'undefined' ? Number.POSITIVE_INFINITY : window.innerHeight * DRAWER_MAX_VH
      setHeight(Math.min(inner.scrollHeight, limit))
    }
    measure()
    window.addEventListener('resize', measure)
    const observer = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    observer?.observe(inner)
    return () => {
      window.removeEventListener('resize', measure)
      observer?.disconnect()
    }
  }, [open])
  return { innerRef, height }
}

// AccountMenu 现在通过 GlobalTopbar 的 drawer 机制展示，不再独立渲染面板


export function GlobalTopbar({
  status,
  action,
  actionTo,
  menuExtra,
  links,
  hideBrandWhenExpanded = false,
}: {
  status: ReactNode
  action?: string
  actionTo?: string
  menuExtra?: ReactNode
  /** 桌面端内联锚点导航：只在页面顶部（顶栏全宽展开态）显示，
      收拢成胶囊后隐去，导航职责交还汉堡菜单。 */
  links?: readonly { label: string; href: string }[]
  hideBrandWhenExpanded?: boolean
}) {
  const { expanded, sentinelRef } = useTopbarExpanded()
  const { status: authStatus, user, logout } = useAuth()
  const navigate = useNavigate()
  const loggedIn = authStatus === 'authenticated'
  
  /* 汉堡菜单与账户菜单共享抽屉：两个按钮互斥，点击任一个都会在胶囊内展开抽屉 */
  const nav = useNavDisclosure()
  const account = useNavDisclosure()
  
  /* 配额数据：仅在账户菜单打开时加载。
     竞态与 stale 防护（#386）：
     - 每次 effect 运行持有独立的 cancelled 守卫，关闭/重开时上一轮 in-flight
       回调（成功与失败分支）作废，旧响应不能覆盖新一轮状态——最新请求胜出；
     - 关闭菜单即清空 entitlements，下次打开先渲染空态，不再闪现上一轮的旧配额。 */
  const [entitlements, setEntitlements] = useState<{ daily: EntitlementItem | null; monthly: EntitlementItem | null } | null>(null)

  useEffect(() => {
    if (!account.open) {
      setEntitlements(null)
      return
    }
    let cancelled = false
    void getEntitlements()
      .then((data) => {
        if (cancelled) return
        const daily = data.entitlements.find((item) => item.key === 'daily_auth') ?? null
        const monthly = data.entitlements.find((item) => item.key === 'monthly_auth') ?? null
        setEntitlements({ daily, monthly })
      })
      .catch(() => {
        if (cancelled) return
        setEntitlements({ daily: null, monthly: null })
      })
    return () => { cancelled = true }
  }, [account.open])
  
  // 点击头像时：关闭汉堡菜单，打开账户抽屉
  const toggleAccount = useCallback(() => {
    if (nav.open) nav.close()
    account.toggle()
  }, [nav, account])
  
  // 点击汉堡时：关闭账户菜单，打开汉堡抽屉
  const toggleNav = useCallback(() => {
    if (account.open) account.close()
    nav.toggle()
  }, [nav, account])
  
  const anyOpen = nav.open || account.open
  /* 450ms = 抽屉收拢 0.45s（遮罩淡出 0.35s 先结束），与 shell css 过渡对齐。
     navPanelClosing / accountPanelClosing 是面板各自的退出窗口：抽屉关闭时
     nav.open / account.open 在渲染第一拍就变 false，若面板内容同拍卸载，
     .is-closing 下的 cx-mask-down / cx-line-out / cx-nav-fade-out
     （chenxing-design-shell.css 537-549）匹配不到任何元素，逐项退出动画
     永远不会执行；两个退出窗口让最后打开的面板在收拢期间保持渲染（#379）。 */
  const navClosing = useExitDelay(anyOpen, 450)
  const navPanelClosing = useExitDelay(nav.open, 450)
  const accountPanelClosing = useExitDelay(account.open, 450)
  const drawer = useAccordionHeight(anyOpen)
  const name = user?.display_name || user?.username || '辰'
  const avatar = avatarUrl(user)
  const memberId = user?.id != null ? `NO.${String(user.id).padStart(6, '0')}` : 'NO.000000'
  const handle = user?.username ? `@${user.username}` : '@user'

  /* 抽屉内容在退出窗口内的面板选择：open 分支优先——「关汉堡同时开账户」这类
     互斥切换必须立即换面板，不能等旧面板的退出窗口结束；两者都关闭时，各自的
     退出窗口选中最后打开的面板，供 .is-closing 逐项退出动画使用（#379）。 */
  const showNavMenu = nav.open || (!account.open && navPanelClosing)
  const showAccountPanel = account.open || (!nav.open && accountPanelClosing)
  
  return (
    <>
      <div ref={sentinelRef} aria-hidden="true" className="chenxing-topbar-sentinel" />
      <header
        className="chenxing-topbar"
        data-expanded={expanded || undefined}
        data-open={anyOpen || undefined}
        data-hide-brand-when-expanded={hideBrandWhenExpanded || undefined}
      >
        {/* 胶囊视觉在内层：外层 header 流内高度固定一行（见 shell css），
            抽屉展开只向下溢出覆盖内容，不改变文档高度与滚动条长度。 */}
        <div className="chenxing-topbar-capsule">
          <div className="chenxing-topbar-row">
            {/* 只留字形：50px 行高里放不下两行中文，且首页 hero、控制台侧栏、
                登录面板都已各自承载完整品牌名，顶栏重复一遍只是挤占密度。 */}
            <Link to="/" className="chenxing-topbar-brand" aria-label="返回首页">
              <BrandMark className="chenxing-topbar-mark" />
            </Link>
            {links?.length ? (
              <nav className="chenxing-topbar-links" aria-label="页面导航">
                {links.map((item) => (
                  <a key={item.href} href={item.href}>{item.label}</a>
                ))}
              </nav>
            ) : null}
            {/* 微标签绝对居中且不吃指针：居中与两侧元素宽度解耦，也永不挡住按钮命中区。
                lamalama 行为：页面最顶部（expanded）时中央不显示任何文字，向下滚动
                顶栏收拢成胶囊的同时，文字以乱码逐位解码的方式出现；滚回顶部随
                容器淡出。字符串状态走 ScrambleText，ReactNode 状态保持原样常驻。 */}
            <div className="chenxing-topbar-status" data-topbar-status data-hidden={expanded || undefined}>
              {typeof status === 'string' ? <ScrambleText text={status} active={!expanded} /> : <span>{status}</span>}
            </div>
            <div className="chenxing-topbar-actions">
              {/* 汉堡按钮：点击时打开导航菜单 */}
              <div className="inline-flex" ref={nav.containerRef}>
                <button
                  ref={nav.buttonRef}
                  type="button"
                  className={`chenxing-hamburger${nav.open ? ' is-open' : ''}`}
                  aria-label="打开导航菜单"
                  aria-expanded={nav.open}
                  aria-controls={nav.panelId}
                  aria-haspopup="true"
                  onClick={toggleNav}
                  onKeyDown={nav.onButtonKeyDown}
                >
                  <span /><span /><span />
                </button>
              </div>
              {/* 头像按钮：点击时收缩并打开账户菜单（在抽屉里显示） */}
              {loggedIn ? (
                <div className="inline-flex" ref={account.containerRef}>
                  <button
                    ref={account.buttonRef}
                    type="button"
                    className={`chenxing-avatar chenxing-avatar-trigger h-11 w-11 text-sm${account.open ? ' is-open' : ''}`}
                    aria-label="账户菜单"
                    aria-expanded={account.open}
                    aria-controls={account.panelId}
                    aria-haspopup="true"
                    onClick={toggleAccount}
                    onKeyDown={account.onButtonKeyDown}
                  >
                    <AvatarContent src={avatar} name={name} />
                  </button>
                </div>
              ) : action && actionTo ? (
                <Link to={actionTo} className="chenxing-topbar-cta">{action}</Link>
              ) : null}
            </div>
          </div>
          {/* 抽屉：显示导航菜单或账户信息 */}
          {(anyOpen || navClosing) ? (
            <div className={`chenxing-topbar-drawer${!anyOpen && navClosing ? ' is-closing' : ''}`} style={{ height: `${drawer.height}px` }}>
              <div ref={drawer.innerRef} className="chenxing-topbar-drawer-inner">
                {showNavMenu ? (
                  <NavMenu
                    id={nav.panelId}
                    panelRef={nav.panelRef}
                    onKeyDown={nav.onPanelKeyDown}
                    extra={menuExtra}
                    onNavigate={nav.close}
                  />
                ) : showAccountPanel ? (
                  <div id={account.panelId} data-menu ref={account.panelRef} onKeyDown={account.onPanelKeyDown} className="chenxing-menu cx-nav-panel cx-account-panel">
                    {/* 用户信息头 */}
                    <div className="cx-account-header">
                      <div className="chenxing-avatar h-20 w-20 text-2xl pointer-events-none">
                        <AvatarContent src={avatar} name={name} />
                      </div>
                      <p className="mt-3 text-base font-semibold text-[var(--chenxing-foreground)]">{name}</p>
                      <div className="mt-2.5 grid grid-cols-2 gap-x-8 text-center text-[11px]">
                        <div>
                          <p className="chenxing-caption uppercase tracking-[0.1em]">会员序列</p>
                          <p className="chenxing-mono mt-0.5 text-[var(--chenxing-foreground)]">{memberId}</p>
                        </div>
                        <div>
                          <p className="chenxing-caption uppercase tracking-[0.1em]">@ Handle</p>
                          <p className="chenxing-mono mt-0.5 text-[var(--chenxing-cyan)]">{handle}</p>
                        </div>
                      </div>
                      
                      {/* 配额卡片 */}
                      {entitlements && (entitlements.daily || entitlements.monthly) ? (
                        <div className="mt-4 w-full space-y-2.5 px-2">
                          {entitlements.daily ? (
                            <div className="cx-quota-card">
                              <div className="flex items-center justify-between">
                                <span className="text-xs text-[var(--chenxing-muted-foreground)]">每日授权调用</span>
                                <span className="chenxing-mono text-xs font-semibold">
                                  {entitlements.daily.used} / {typeof entitlements.daily.limit === 'number' ? entitlements.daily.limit : '∞'}
                                </span>
                              </div>
                            </div>
                          ) : null}
                          {entitlements.monthly ? (
                            <div className="cx-quota-card">
                              <div className="flex items-center justify-between">
                                <span className="text-xs text-[var(--chenxing-muted-foreground)]">每月授权调用</span>
                                <span className="chenxing-mono text-xs font-semibold">
                                  {entitlements.monthly.used} / {typeof entitlements.monthly.limit === 'number' ? entitlements.monthly.limit : '∞'}
                                </span>
                              </div>
                            </div>
                          ) : null}
                        </div>
                      ) : null}
                    </div>
                    
                    {/* 菜单项 */}
                    <div className="p-2">
                      <Link to="/console/profile" className="chenxing-menu-item" onClick={account.close}>
                        <Icon name="user" className="text-[var(--chenxing-cyan)]" size={16} />账户设置
                      </Link>
                      <Link to="/console/plans" className="chenxing-menu-item" onClick={account.close}>
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
                          account.close()
                          void logout().then(() => navigate('/login'))
                        }}
                      >
                        <Icon name="log-out" className="text-[var(--chenxing-error)]" size={16} />退出
                      </button>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}
        </div>
      </header>
      {/* 遮罩只剩压暗+模糊背景这一职责（面板已移进胶囊）。它必须是顶栏的兄弟节点：
          backdrop-filter 的模糊会作用于其下绘制的一切，而 DOM 祖先永远先于后代
          绘制，遮罩若嵌在顶栏内部，顶栏就无法靠 z-index 逃出模糊。做兄弟节点后
          两者同处一个层叠上下文，--chenxing-z-topbar(55) > --chenxing-z-menu(50)
          生效，胶囊连同展开的抽屉一起保持清晰。 */}
      {(anyOpen || navClosing) ? (
        <div 
          className={`cx-menu-overlay${anyOpen ? ' is-open' : ''}`} 
          onClick={() => {
            nav.close()
            account.close()
          }} 
          aria-hidden="true" 
        />
      ) : null}
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
  links,
}: {
  children: ReactNode
  status: ReactNode
  action?: string
  actionTo?: string
  className?: string
  menuExtra?: ReactNode
  links?: readonly { label: string; href: string }[]
}) {
  /* 跳过链接是 Shell 的第一个可聚焦元素，内容锚点紧跟顶栏之后（见 skip-link.tsx） */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className={className} opacity={0.7}>
      <SkipLink targetId={targetId} />
      <GlobalTopbar status={status} action={action} actionTo={actionTo} menuExtra={menuExtra} links={links} />
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

/** 桌面侧栏导航分组：按角色过滤可见分组，渲染带 active 态的导航项。
    移动端不再复用它——汉堡菜单只保留区域级入口（控制台/开发者/管理），
    区域内页面切换由底栏承载。 */
function ConsoleNavGroups() {
  const { user } = useAuth()
  const location = useLocation()
  /* 管理/系统分组只对已登录的管理角色显示；user 为 null 时必须显式排除，
     与 NavMenu 的 showAdmin 判定保持一致（user?.role !== 'user' 在 null 时恒真） */
  const showAdmin = user != null && user.role !== 'user'
  const visible = navGroups.filter(
    (group) => group.label === '账户' || group.label === '开发者' || showAdmin,
  )
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

/** 移动端底栏按当前区域切换：账户区显示「总览 / 个人信息 / 已授权应用」，
    开发者区显示「接入应用 / 授权测试 / 套餐与权益」，管理区（/admin*）显示
    管理与系统分组的四项；桌面端由 CSS 隐藏。 */
function BottomNav() {
  const location = useLocation()
  const groupItems = (label: string) => navGroups.find((group) => group.label === label)?.items ?? []
  const developer = groupItems('开发者')
  const core = location.pathname.startsWith('/admin')
    ? [...groupItems('管理'), ...groupItems('系统')]
    : developer.some((item) => item.path === location.pathname)
      ? developer
      : groupItems('账户')
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
            appears once the bar condenses into its capsule
            所有区域入口（控制台/开发者/管理）都在 NavMenu 本体里，无需 menuExtra */}
        <GlobalTopbar status={status} hideBrandWhenExpanded />
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
