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
import { Link } from '../router'
import { useAuth } from '../auth-state'
import { Icon } from './ui'

/* 汉堡/账户下拉的共享可访问性逻辑，实现 WAI-ARIA Disclosure Navigation 模式
   （面板里是导航链接/按钮，不是 role="menu"，因此不用 menu 小部件语义）：
   - 触发器带 aria-expanded / aria-controls / aria-haspopup，useId 保证多实例不重复；
   - 点击面板外部关闭（沿用原 mousedown 行为）；
   - Escape 关闭并把焦点还给触发器按钮；
   - 面板内 ArrowDown/ArrowUp 循环移动焦点，Home/End 跳首尾；
   - 在触发器上按 ArrowDown/ArrowUp 打开面板并把焦点移进首/末项。 */
export function useNavDisclosure() {
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
export function useTopbarExpanded() {
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

export function NavMenu({ id, panelRef, onKeyDown, extra, onNavigate }: {
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
export function useExitDelay(open: boolean, ms: number) {
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

export function useAccordionHeight(open: boolean) {
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
