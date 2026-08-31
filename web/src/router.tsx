import { useEffect, useSyncExternalStore, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

export const HISTORY_INDEX = '__chenxing_history_index'
export const NAVIGATION_EVENT = 'chenxing:navigation'

export type RouterLocation = { pathname: string; search: string }

/**
 * 位置状态的单一来源（#686）。
 *
 * 组件不再各自监听原生 popstate：路由器是 popstate 的唯一消费者，渲染只跟随
 * 这里的「已提交快照」。被守卫拒绝的后退/前进不会推进快照，因此设置页组件实例
 * 不会卸载，未保存草稿也就不会丢。
 */
let committed: RouterLocation = readWindowLocation()
let historyIndex = typeof window === 'undefined' ? 0 : (readEntryIndex(window.history.state) ?? 0)
/** history.go 回滚自身也会派发 popstate；这个标记让回滚事件不被当成新的 traversal。 */
let restoringHistory = false
/**
 * 拒绝离开后的回滚窗口。浏览器此刻已经停在目标条目上（popstate 无法取消），
 * 但守卫说不许离开，所以快照必须冻结在原位置：任何在这段时间里发生的渲染
 * 都不能读到目标 URL，否则设置页会先卸载一次，回滚后再挂载一个空白实例。
 */
let locationFrozen = false
/**
 * 回滚的重试预算。用户连按后退时，第二次 traversal 会排在我们的回滚 go() 之前到达，
 * 此时位置还没回到已提交条目，必须继续往回推而不是当成回滚完成——否则受保护的页面
 * 仍会被卸载。预算有限，保证异常历史栈不会把标签页卷进无限 go 循环。
 */
const MAX_RESTORE_ATTEMPTS = 8
let restoreAttempts = 0
const locationListeners = new Set<() => void>()
let navigationBlocker: (() => boolean) | null = null

/** 条目索引只存在于我们自己写入的 history.state；外部条目没有它。 */
function readEntryIndex(state: unknown): number | null {
  const value = (state as Record<string, unknown> | null | undefined)?.[HISTORY_INDEX]
  return typeof value === 'number' ? value : null
}

function readWindowLocation(): RouterLocation {
  if (typeof window === 'undefined') return { pathname: '/', search: '' }
  return { pathname: window.location.pathname, search: window.location.search }
}

/**
 * useSyncExternalStore 的 getSnapshot：未冻结时按值同步浏览器地址，
 * 值没变就返回同一个对象，避免快照身份抖动导致无限重渲染。
 *
 * 冻结期间连 publish 也不推进快照：回滚完成后地址会回到已提交位置，
 * 保持「渲染位置 == 浏览器位置」的一致收敛。
 */
function readCommittedLocation(): RouterLocation {
  if (locationFrozen) return committed
  const next = readWindowLocation()
  if (next.pathname !== committed.pathname || next.search !== committed.search) committed = next
  return committed
}

function publishLocation() {
  readCommittedLocation()
  for (const listener of [...locationListeners]) listener()
}

function subscribeLocation(listener: () => void) {
  locationListeners.add(listener)
  return () => { locationListeners.delete(listener) }
}

if (typeof window !== 'undefined' && readEntryIndex(window.history.state) !== historyIndex) {
  window.history.replaceState({ ...(window.history.state ?? {}), [HISTORY_INDEX]: historyIndex }, '', window.location.href)
}

function commitHistory(to: string, options?: NavigationOptions) {
  const index = options?.replace ? historyIndex : historyIndex + 1
  historyIndex = index
  const state = { ...(window.history.state ?? {}), [HISTORY_INDEX]: index }
  if (options?.replace) window.history.replaceState(state, '', to)
  else window.history.pushState(state, '', to)
}

/**
 * 导航通知仍走 window 事件：api.ts 的 401 重定向与 auth 的 URL 清理都依赖它，
 * 且测试逐字断言事件名。路由器自身作为该事件的订阅者推进快照。
 */
function notifyNavigation() {
  window.dispatchEvent(new Event(NAVIGATION_EVENT))
}

/**
 * 询问守卫，并在询问期间就冻结快照。
 *
 * 冻结必须在事件处理函数返回之前生效：守卫或其它 popstate 监听器可能触发 setState，
 * React 会在原生事件处理结束时冲刷这批更新，此时浏览器地址已是目标 URL 而回滚尚未发生。
 * 守卫自身抛错时按放行处理，绝不能把路由器留在永久冻结状态。
 */
function allowsLeaving(): boolean {
  locationFrozen = true
  try {
    return navigationBlocker ? navigationBlocker() : true
  } catch {
    return true
  }
}

/**
 * 浏览器 traversal 的唯一处理点。
 *
 * 顺序是：冻结快照 → 询问守卫 → 允许才解冻并提交。守卫拒绝时用 history.go(delta)
 * 把浏览器历史送回原条目；回滚事件到达时只解除冻结，快照仍是原来那一个，
 * 因此整个过程中没有任何组件被卸载，草稿状态原地存活。
 */
function handlePopstate(event: PopStateEvent) {
  // 缺索引的条目（非本路由器写入）按后退一格推断，沿用 #622 起的行为。
  const targetIndex = readEntryIndex(event.state) ?? historyIndex - 1
  const delta = historyIndex - targetIndex
  if (restoringHistory) {
    if (delta !== 0 && restoreAttempts < MAX_RESTORE_ATTEMPTS) {
      // 回滚还没落回已提交条目（用户连按后退时，后一次 traversal 会插在回滚之前到达）：
      // 继续往回推，不重复询问守卫、也不解冻，受保护的页面依旧不卸载。
      restoreAttempts += 1
      window.history.go(delta)
      return
    }
    restoringHistory = false
    restoreAttempts = 0
    locationFrozen = false
    // 正常情况下地址已回到已提交条目，快照按值比较不变，React 直接 bail out：
    // 没有任何组件被卸载或重挂。publish 仍然要做，冻结期间的 replaceUrl 改写才不会被吞掉。
    // 超出重试预算时以浏览器实际位置为准，绝不把路由器留在永久冻结状态。
    historyIndex = targetIndex
    publishLocation()
    return
  }
  // delta 为 0 时无处可回滚，也不能调 go(0)（真实浏览器里等同 reload），
  // 冻结只会让渲染永久停在旧位置；这种 traversal 直接按接受处理。
  if (delta !== 0 && !allowsLeaving()) {
    restoringHistory = true
    restoreAttempts = 0
    window.history.go(delta)
    return
  }
  locationFrozen = false
  historyIndex = targetIndex
  publishLocation()
}

if (typeof window !== 'undefined') {
  window.addEventListener('popstate', handlePopstate)
  window.addEventListener(NAVIGATION_EVENT, publishLocation)
}

/**
 * 路由级导航拦截器：本项目没有 react-router，这是 useBlocker 的自制等价物。
 * navigate 是 Link 点击与程序化跳转的唯一入口，跳转前询问已注册的拦截器，
 * 返回 false 时放弃本次导航。设置页用它实现「有未保存草稿时离开需确认」。
 * 同一时刻只允许一个拦截器（当前只有设置页需要注册）。
 *
 * replace 选项（#326）：守卫重定向（未登录、无权限、未知路径）必须用
 * replaceState 覆盖当前条目，否则用户按后退会回到刚被守卫踢走的页面，
 * 再次触发重定向，永远回不到目标页之前的正常历史。
 */
export type NavigationOptions = { replace?: boolean }

/**
 * A navigation that has already passed the current blocker. The commit is
 * deliberately one-shot so an async workflow (logout, save, etc.) cannot
 * accidentally replay the same history mutation or re-run the blocker.
 */
export type NavigationIntent = {
  commit: (to?: string, options?: NavigationOptions) => boolean
}

export function setNavigationBlocker(blocker: (() => boolean) | null) {
  navigationBlocker = blocker
}

export function prepareNavigation(to: string, options?: NavigationOptions): NavigationIntent | null {
  if (navigationBlocker && !navigationBlocker()) return null

  let committedIntent = false
  return {
    commit(nextTo = to, nextOptions = options) {
      if (committedIntent) return false
      committedIntent = true
      commitHistory(nextTo, nextOptions)
      notifyNavigation()
      return true
    },
  }
}

export function navigate(to: string, options?: NavigationOptions) {
  const intent = prepareNavigation(to, options)
  if (!intent) return
  // 守卫重定向必须走 replaceState（#326）：push 会把被拦截的目标页留在历史里，
  // 用户在登录页按后退又撞回该页、守卫再次跳转，形成永远回不去的重定向陷阱。
  // 用户主动点击的链接仍用 pushState，保留正常的前进/后退语义。
  intent.commit()
}

/**
 * Replace the current same-document URL without creating a history entry.
 *
 * URL cleanup and auth redirects still need to re-render the SPA, but they are
 * not browser history traversals and must not run the popstate blocker.
 */
export function replaceUrl(to: string) {
  commitHistory(to, { replace: true })
  notifyNavigation()
}

export function useLocation(): RouterLocation {
  return useSyncExternalStore(subscribeLocation, readCommittedLocation, readCommittedLocation)
}

export function usePathname() {
  return useLocation().pathname
}

export function useNavigate() { return navigate }

type LinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & { to: string; children?: ReactNode }

export function Link({ to, onClick, children, ...props }: LinkProps) {
  const handleClick = (event: MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event)
    if (event.defaultPrevented || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || to.startsWith('http')) return
    event.preventDefault()
    navigate(to)
  }
  return <a href={to} onClick={handleClick} {...props}>{children}</a>
}

type NavLinkProps = Omit<LinkProps, 'className'> & { className?: string | ((state: { isActive: boolean }) => string) }

export function NavLink({ to, className, ...props }: NavLinkProps) {
  const active = useLocation().pathname === to
  const resolvedClass = typeof className === 'function' ? className({ isActive: active }) : className
  return <Link to={to} className={resolvedClass} aria-current={active ? 'page' : undefined} {...props} />
}

export function Navigate({ to, replace = false }: { to: string; replace?: boolean }) {
  useEffect(() => navigate(to, { replace }), [to, replace])
  return null
}
