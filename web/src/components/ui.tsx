import type { ReactNode } from 'react'
import {
  ArrowRight, ArrowUpRight, Check, Circle, CircleAlert, Code2, Copy, Crown, FlaskConical,
  Download, Gauge, KeyRound, LayoutDashboard, LayoutGrid, LogIn, LogOut, Mail, Menu, MoreHorizontal,
  Orbit, RadioTower, RefreshCw, Rocket, Save, Search, Send, Settings, ShieldCheck, Sparkles, Store, User,
  Users, X, type LucideIcon,
} from 'lucide-react'
import logoUrl from '../../../design-auth-chengming/assets/logo.png'

const icons: Record<string, LucideIcon> = {
  'arrow-right': ArrowRight, 'arrow-up-right': ArrowUpRight, check: Check, 'circle-alert': CircleAlert,
  circle: Circle, 'code-2': Code2, copy: Copy, crown: Crown, 'flask-conical': FlaskConical,
  download: Download, gauge: Gauge, 'key-round': KeyRound, 'layout-dashboard': LayoutDashboard, 'layout-grid': LayoutGrid,
  'log-in': LogIn, 'log-out': LogOut, mail: Mail, menu: Menu, orbit: Orbit, 'radio-tower': RadioTower,
  'more-horizontal': MoreHorizontal, rocket: Rocket, 'refresh-cw': RefreshCw, save: Save, send: Send,
  search: Search, settings: Settings, 'shield-check': ShieldCheck, sparkles: Sparkles,
  store: Store, user: User, users: Users, x: X,
}

export function Icon({ name, size = 18, strokeWidth = 1.8 }: { name: string; size?: number; strokeWidth?: number }) {
  const Component = icons[name] ?? Circle
  return <Component size={size} strokeWidth={strokeWidth} aria-hidden="true" />
}

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <span className="brand-lockup">
      <img src={logoUrl} alt="天穹辰星" className="brand-logo" />
      {!compact && <span><strong className="brand-name">天穹辰星</strong><small>辰星认证中枢</small></span>}
    </span>
  )
}

export function HudPanel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`chenxing-hud-panel ${className}`}>{children}</div>
}

type ButtonProps = import('react').ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger'
  icon?: string
}

export function Button({ variant = 'primary', icon, children, className = '', ...props }: ButtonProps) {
  return (
    <button className={`chenxing-btn-${variant} ${className}`} {...props}>
      {icon && <Icon name={icon} size={16} />}
      {children}
    </button>
  )
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' }) {
  return <span className={`chenxing-badge${tone === 'success' ? '-success' : tone === 'warning' ? '-warning' : ''}`}>{children}</span>
}

export function Field({ label, hint, ...props }: React.InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: string }) {
  return (
    <label className="field">
      <span className="chenxing-label">{label}</span>
      <input {...props} />
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  )
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return (
    <header className="page-header">
      <div><span className="eyebrow">{eyebrow}</span><h1 className="chenxing-h1">{title}</h1><p className="page-description">{description}</p></div>
      {action}
    </header>
  )
}

export function Notice({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'success' | 'warning' }) {
  return <div className={`notice notice-${tone}`}><Icon name={tone === 'success' ? 'check' : tone === 'warning' ? 'circle-alert' : 'sparkles'} size={17} /> <span>{children}</span></div>
}

export function CopyValue({ value }: { value: string }) {
  const copy = async () => { await navigator.clipboard?.writeText(value) }
  return <button className="copy-value" type="button" onClick={copy} title="复制"><span>{value}</span><Icon name="copy" size={15} /></button>
}

export function Background({ children }: { children: ReactNode }) {
  return <main className="app-background"><div className="space-grid" aria-hidden="true" /><div className="space-glow" aria-hidden="true" />{children}</main>
}
