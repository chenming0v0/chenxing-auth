import { useEffect, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

function currentPath() { return window.location.pathname }

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

export function setNavigationBlocker(blocker: (() => boolean) | null) {
  navigationBlocker = blocker
}

export function navigate(to: string, options: { replace?: boolean } = {}) {
  if (navigationBlocker && !navigationBlocker()) return
  if (options.replace) {
    window.history.replaceState({}, '', to)
  } else {
    window.history.pushState({}, '', to)
  }
  window.dispatchEvent(new PopStateEvent('popstate'))
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
