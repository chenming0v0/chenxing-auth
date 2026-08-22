import { useEffect, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

function currentPath() { return window.location.pathname }

const HISTORY_INDEX = '__chenxing_history_index'
let historyIndex = typeof window !== 'undefined' && typeof window.history.state?.[HISTORY_INDEX] === 'number'
  ? window.history.state[HISTORY_INDEX] as number
  : 0
let restoringHistory = false
let skipNextProgrammaticPopstate = false
if (typeof window !== 'undefined' && window.history.state?.[HISTORY_INDEX] !== historyIndex) {
  window.history.replaceState({ ...(window.history.state ?? {}), [HISTORY_INDEX]: historyIndex }, '', window.location.href)
}

function commitHistory(to: string, options?: NavigationOptions) {
  const index = options?.replace ? historyIndex : historyIndex + 1
  historyIndex = index
  const state = { ...(window.history.state ?? {}), [HISTORY_INDEX]: index }
  if (options?.replace) window.history.replaceState(state, '', to)
  else window.history.pushState(state, '', to)
}

function installPopstateGuard() {
  if (typeof window === 'undefined') return
  window.addEventListener('popstate', (event) => {
    if (skipNextProgrammaticPopstate) {
      skipNextProgrammaticPopstate = false
      return
    }
    if (restoringHistory) {
      restoringHistory = false
      return
    }
    const targetIndex = typeof event.state?.[HISTORY_INDEX] === 'number'
      ? event.state[HISTORY_INDEX] as number
      : historyIndex - 1
    if (navigationBlocker && !navigationBlocker()) {
      const delta = historyIndex - targetIndex
      if (delta !== 0) {
        restoringHistory = true
        window.history.go(delta)
      }
      return
    }
    historyIndex = targetIndex
  })
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
let navigationBlocker: (() => boolean) | null = null
installPopstateGuard()

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

  let committed = false
  return {
    commit(nextTo = to, nextOptions = options) {
      if (committed) return false
      committed = true
      commitHistory(nextTo, nextOptions)
      skipNextProgrammaticPopstate = true
      window.dispatchEvent(new PopStateEvent('popstate'))
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

export function usePathname() {
  const [path, setPath] = useState(currentPath)
  useEffect(() => { const update = () => setPath(currentPath()); window.addEventListener('popstate', update); return () => window.removeEventListener('popstate', update) }, [])
  return path
}

export function useNavigate() { return navigate }
export function useLocation() {
  const pathname = usePathname()
  const [search, setSearch] = useState(window.location.search)
  useEffect(() => {
    const update = () => setSearch(window.location.search)
    window.addEventListener('popstate', update)
    return () => window.removeEventListener('popstate', update)
  }, [])
  return { pathname, search }
}

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
