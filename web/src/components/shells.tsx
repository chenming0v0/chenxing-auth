import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus, initialOf } from '../data'
import { BrandLockup, BrandMark, Button, HudPanel, Icon, Notice } from './ui'
import { SpaceBackdrop } from './space'

function useClickAway(open: boolean, onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onPointer = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) onClose()
    }
    document.addEventListener('mousedown', onPointer)
    return () => document.removeEventListener('mousedown', onPointer)
  }, [open, onClose])
  return ref
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

function NavMenu({ extra }: { extra?: ReactNode }) {
  return (
    <div data-menu className="chenxing-menu absolute right-0 top-full z-50 mt-3 w-60">
      <Link to="/" className="chenxing-nav-menu-item">主页<Icon name="arrow-up-right" size={16} /></Link>
      <Link to="/console" className="chenxing-nav-menu-item">控制台<Icon name="layout-dashboard" size={16} /></Link>
      <button type="button" className="chenxing-nav-menu-item">应用广场<Icon name="store" size={16} /></button>
      <div className="chenxing-divider my-1" />
      <div className="flex items-center justify-between px-3.5 py-2">
        <span className="chenxing-caption text-[11px] tracking-[0.06em]">状态</span>
        <span className="chenxing-caption inline-flex items-center gap-2 text-[11px] tracking-[0.06em] text-[var(--chenxing-success)]">
          <span className="chenxing-status-dot" />星门在线
        </span>
      </div>
      {extra}
    </div>
  )
}

function HamburgerMenu({ extra }: { extra?: ReactNode }) {
  const [open, setOpen] = useState(false)
  const ref = useClickAway(open, () => setOpen(false))
  return (
    <div className="relative" ref={ref}>
      <button type="button" className="chenxing-hamburger" aria-label="打开导航菜单" onClick={() => setOpen((value) => !value)}>
        <span /><span /><span />
      </button>
      {open ? <NavMenu extra={extra} /> : null}
    </div>
  )
}

function AccountMenu() {
  const [open, setOpen] = useState(false)
  const ref = useClickAway(open, () => setOpen(false))
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const name = user?.display_name || user?.username || '辰'
  const memberId = user?.id != null ? `NO.${String(user.id).padStart(6, '0')}` : 'NO.000000'
  const handle = user?.username ? `@${user.username}` : '@user'
  return (
    <div className="relative" ref={ref}>
      <button type="button" className="chenxing-avatar h-9 w-9 text-sm" aria-label="账户菜单" onClick={() => setOpen((value) => !value)}>
        {initialOf(name)}
      </button>
      {open ? (
        <div className="chenxing-menu absolute right-0 top-full z-50 mt-3 w-64 p-0 overflow-hidden">
          {/* ── 用户信息头 ── */}
          <div className="chenxing-account-header">
            <div className="chenxing-avatar h-14 w-14 text-lg pointer-events-none">
              {initialOf(name)}
            </div>
            <h3 className="mt-2 text-sm font-semibold text-[var(--chenxing-foreground)]">{name}</h3>
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
            <Link to="/console/profile" className="chenxing-menu-item" onClick={() => setOpen(false)}>
              <Icon name="user" className="text-[var(--chenxing-cyan)]" size={16} />账户设置
            </Link>
            <Link to="/console/plans" className="chenxing-menu-item" onClick={() => setOpen(false)}>
              <Icon name="receipt" className="text-[var(--chenxing-cyan)]" size={16} />套餐订阅
            </Link>
            <button type="button" className="chenxing-menu-item">
              <Icon name="book-open" className="text-[var(--chenxing-cyan)]" size={16} />文档中心
            </button>
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
  loggedIn = false,
  menuExtra,
}: {
  status: string
  action?: string
  actionTo?: string
  loggedIn?: boolean
  menuExtra?: ReactNode
}) {
  const { expanded, sentinelRef } = useTopbarExpanded()
  return (
    <>
      <div ref={sentinelRef} aria-hidden="true" className="chenxing-topbar-sentinel" />
      <header className="chenxing-topbar" data-expanded={expanded || undefined}>
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
  return (
    <SpaceBackdrop className={className} opacity={0.7}>
      <GlobalTopbar status={status} action={action} actionTo={actionTo} menuExtra={menuExtra} />
      {children}
    </SpaceBackdrop>
  )
}

export function AuthPanel({ children, className = 'w-full max-w-md' }: { children: ReactNode; className?: string }) {
  return (
    <section className="relative z-10 flex flex-1 items-center justify-center px-6 py-14 lg:px-12">
      <div className={className}>
        <HudPanel>{children}</HudPanel>
        <p className="chenxing-mono mt-6 text-center text-[10px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]">
          Encrypted Gateway · 天穹辰星
        </p>
      </div>
    </section>
  )
}

function Sidebar() {
  const { user } = useAuth()
  const location = useLocation()
  const visible = navGroups.filter((group) => group.label === '账户' || group.label === '开发者' || user?.role !== 'user')
  return (
    <aside className="chenxing-sidebar flex">
      <Link to="/" className="flex items-center gap-3 px-2">
        <BrandLockup subtitle="用户中心" compact />
      </Link>
      <nav className="chenxing-sidebar-scroll mt-5 no-scrollbar">
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
      </nav>
    </aside>
  )
}

export function ConsoleLayout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const status = pageStatus[location.pathname] || (location.pathname.startsWith('/admin') ? '管理' : '控制台')
  return (
    <SpaceBackdrop className="console-shell" opacity={0.4} dense>
      <Sidebar />
      <div className="chenxing-console-main relative z-10 flex min-h-screen flex-col">
        <GlobalTopbar status={status} loggedIn />
        <div className="chenxing-console-content flex-1 px-4 py-6 pb-10 sm:px-6 lg:px-8">
          {children}
        </div>
      </div>
    </SpaceBackdrop>
  )
}

export function OAuthShell({ children, footer = true }: { children: ReactNode; footer?: boolean }) {
  return (
    <SpaceBackdrop opacity={0.6}>
      <section className="oauth-shell">
        {children}
        {footer ? (
          <div className="oauth-footer">
            <button type="button" aria-haspopup="listbox">简体中文 ▾</button>
            <div className="oauth-footer-links">
              <a href="#">帮助</a>
              <a href="#">隐私权</a>
              <a href="#">条款</a>
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
