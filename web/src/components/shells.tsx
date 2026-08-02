import { useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation } from '../router'
import { navGroups } from '../data'
import { Background, Brand, Button, Icon } from './ui'

export function PublicTopbar({ action, actionTo = '/login' }: { action?: string; actionTo?: string }) {
  const [open, setOpen] = useState(false)
  return (
    <header className="public-topbar">
      <Link to="/"><Brand /></Link>
      <div className="topbar-status"><span className="chenxing-status-dot" />星门在线</div>
      <div className="topbar-actions">
        <button type="button" className="icon-button" onClick={() => setOpen(!open)} aria-label="打开导航菜单"><Icon name="menu" /></button>
        {action && <Link to={actionTo}><Button icon={actionTo === '/login' ? 'log-in' : 'rocket'}>{action}</Button></Link>}
      </div>
      {open && <div className="topbar-menu chenxing-hud-panel"><Link to="/">主页 <Icon name="arrow-up-right" size={15} /></Link><Link to="/console">控制台 <Icon name="layout-dashboard" size={15} /></Link><span className="menu-divider" /><span className="menu-state"><span className="chenxing-status-dot" />认证服务正常</span></div>}
    </header>
  )
}

export function AuthShell({ children, action, actionTo }: { children: ReactNode; action?: string; actionTo?: string }) {
  return <Background><PublicTopbar action={action} actionTo={actionTo} /><div className="public-content">{children}</div></Background>
}

function Sidebar() {
  const location = useLocation()
  return (
    <aside className="chenxing-sidebar">
      <Link to="/" className="sidebar-brand"><Brand /></Link>
      <nav className="sidebar-nav">
        {navGroups.map((group) => <div className="nav-group" key={group.label}>
          <p className="chenxing-nav-label">{group.label}</p>
          {group.items.map((item) => <NavLink key={item.path} to={item.path} className="chenxing-nav-item" aria-current={location.pathname === item.path ? 'page' : undefined}><Icon name={item.icon} size={17} />{item.label}</NavLink>)}
        </div>)}
      </nav>
      <div className="sidebar-footer"><span className="chenxing-status-dot" /><span><strong>星门在线</strong><small>API 服务稳定</small></span></div>
    </aside>
  )
}

function ConsoleTopbar() {
  const [open, setOpen] = useState(false)
  const location = useLocation()
  const current = navGroups.flatMap((group) => group.items).find((item) => item.path === location.pathname)?.label ?? '总览'
  return <header className="console-topbar"><div className="topbar-current"><span className="chenxing-status-dot" />{location.pathname.startsWith('/admin') ? '管理' : '控制台'} · {current}</div><div className="console-top-actions"><button type="button" className="icon-button" onClick={() => setOpen(!open)} aria-label="打开快捷菜单"><Icon name="menu" /></button><button type="button" className="avatar-button" aria-label="账户菜单">辰</button>{open && <div className="console-menu chenxing-hud-panel"><Link to="/console/profile"><Icon name="user" size={15} />个人设置</Link><Link to="/console/integrate"><Icon name="code-2" size={15} />接入应用</Link><Link to="/login"><Icon name="log-out" size={15} />退出登录</Link></div>}</div></header>
}

export function ConsoleLayout({ children }: { children: ReactNode }) {
  return <Background><Sidebar /><section className="chenxing-console-main"><ConsoleTopbar /><div className="console-content">{children}</div></section></Background>
}

export function AuthPanel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`auth-panel chenxing-hud-panel ${className}`}>{children}</div>
}
