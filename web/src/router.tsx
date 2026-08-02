import { useEffect, useState, type AnchorHTMLAttributes, type MouseEvent, type ReactNode } from 'react'

function currentPath() { return window.location.pathname }

export function navigate(to: string) {
  window.history.pushState({}, '', to)
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

export function Navigate({ to }: { to: string }) {
  useEffect(() => navigate(to), [to])
  return null
}
