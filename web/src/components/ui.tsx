import { useState } from 'react'
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react'
import {
  Activity, AlertTriangle, ArrowRight, ArrowUpRight, BadgeCheck, BookOpen, Box, CalendarClock, Check, ChevronDown,
  ChevronsUpDown, Circle, CircleAlert, Code2, Copy, Crown, Database, Download, ExternalLink, Eye, EyeOff, Fingerprint,
  FlaskConical, Gauge, Globe, Info, KeyRound, LayoutDashboard, LayoutGrid, Layers, Link2, Lock, LockKeyhole,
  LogIn, LogOut, Mail, Menu, MoreHorizontal, Pencil, Plus, Power, Receipt, RefreshCw, Rocket, RotateCcw, Save, Search,
  Send, Server, Settings, Settings2, Shield, ShieldAlert, ShieldCheck, Sparkles, Star, Store, Terminal, Trash2, Unlink,
  User, UserPlus, Users, Wallet, X, Zap, type LucideIcon,
} from 'lucide-react'
import logoUrl from '../assets/logo.png'

const icons: Record<string, LucideIcon> = {
  activity: Activity, 'alert-triangle': AlertTriangle, 'arrow-right': ArrowRight, 'arrow-up-right': ArrowUpRight,
  'badge-check': BadgeCheck, 'book-open': BookOpen, box: Box, 'calendar-clock': CalendarClock, check: Check,
  'chevron-down': ChevronDown, 'chevrons-up-down': ChevronsUpDown, circle: Circle, 'circle-alert': CircleAlert,
  'code-2': Code2, copy: Copy, crown: Crown, database: Database, download: Download, 'external-link': ExternalLink,
  eye: Eye, 'eye-off': EyeOff, fingerprint: Fingerprint, 'flask-conical': FlaskConical, gauge: Gauge, github: Code2, globe: Globe,
  info: Info, 'key-round': KeyRound, 'layout-dashboard': LayoutDashboard, 'layout-grid': LayoutGrid, layers: Layers,
  link: Link2, lock: Lock, 'lock-keyhole': LockKeyhole, 'log-in': LogIn, 'log-out': LogOut, mail: Mail, menu: Menu,
  'more-horizontal': MoreHorizontal, pencil: Pencil, plus: Plus, power: Power, receipt: Receipt, 'refresh-cw': RefreshCw,
  rocket: Rocket, 'rotate-ccw': RotateCcw, save: Save, search: Search, send: Send, server: Server, settings: Settings,
  'settings-2': Settings2, shield: Shield, 'shield-alert': ShieldAlert, 'shield-check': ShieldCheck, sparkles: Sparkles,
  star: Star, store: Store, terminal: Terminal, 'trash-2': Trash2, unlink: Unlink, user: User, 'user-plus': UserPlus,
  users: Users, wallet: Wallet, x: X, zap: Zap,
}

export function Icon({ name, size = 16, className = '', strokeWidth = 1.8 }: { name: string; size?: number; className?: string; strokeWidth?: number }) {
  const Component = icons[name] ?? Circle
  return <Component size={size} strokeWidth={strokeWidth} className={className} aria-hidden="true" />
}

export function BrandMark({ className = 'h-8 w-8 rounded-[var(--chenxing-radius-md)]' }: { className?: string }) {
  return <img src={logoUrl} alt="天穹辰星" className={className} />
}

export function BrandLockup({ subtitle = '辰星认证中枢', compact = false }: { subtitle?: string; compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark className={compact ? 'chenxing-brand-logo' : 'h-8 w-8 rounded-[var(--chenxing-radius-md)]'} />
      <span className={compact ? undefined : 'hidden sm:block'}>
        <span className={compact ? 'chenxing-wordmark text-aurora block text-base' : 'chenxing-body block text-sm font-semibold leading-tight'}>天穹辰星</span>
        <span className={compact ? 'chenxing-mono block text-[9px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]' : 'chenxing-caption block text-[10px] leading-tight tracking-[0.08em]'}>{subtitle}</span>
      </span>
    </span>
  )
}

export function HudPanel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`chenxing-hud-panel ${className}`}>{children}</div>
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger'
  icon?: string
}

export function Button({ variant = 'primary', icon, children, className = '', ...props }: ButtonProps) {
  return (
    <button type="button" className={`chenxing-btn-${variant} ${className}`} {...props}>
      {icon ? <Icon name={icon} size={16} /> : null}
      {children}
    </button>
  )
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' }) {
  const cls = tone === 'success' ? 'chenxing-badge-success' : tone === 'warning' ? 'chenxing-badge-warning' : 'chenxing-badge'
  return <span className={cls}>{children}</span>
}

export function Chip({ children, onRemove }: { children: ReactNode; onRemove?: () => void }) {
  return (
    <span className="chenxing-chip">
      {children}
      {onRemove ? (
        <button type="button" className="ml-1 inline-flex" onClick={onRemove} aria-label="移除">
          <Icon name="x" size={12} />
        </button>
      ) : null}
    </span>
  )
}

export function Switch({
  checked,
  onChange,
  disabled = false,
  label,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
  label?: string
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      className={`chenxing-switch${checked ? ' is-on' : ''}${disabled ? ' opacity-50' : ''}`}
      onClick={() => onChange(!checked)}
    />
  )
}

export function ToggleRow({
  title,
  description,
  checked,
  onChange,
  disabled = false,
}: {
  title: string
  description?: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
      <div>
        <p className="chenxing-body text-sm font-semibold">{title}</p>
        {description ? <p className="chenxing-caption mt-0.5">{description}</p> : null}
      </div>
      <Switch checked={checked} onChange={onChange} disabled={disabled} label={title} />
    </div>
  )
}

export function Notice({ children, tone = 'info' }: { children: ReactNode; tone?: 'info' | 'success' | 'warning' }) {
  const icon = tone === 'success' ? 'check' : tone === 'warning' ? 'alert-triangle' : 'info'
  return (
    <div className={`cx-alert cx-alert-${tone}`}>
      <Icon name={icon} size={16} className="mt-0.5 shrink-0" />
      <div className="chenxing-caption text-[var(--chenxing-foreground)]">{children}</div>
    </div>
  )
}

export function FieldShell({ icon, trailing, error, children }: { icon?: string; trailing?: ReactNode; error?: boolean; children: ReactNode }) {
  return (
    <div className={`chenxing-field-shell${error ? ' chenxing-field-error' : ''}`}>
      {icon ? <Icon name={icon} className="chenxing-field-icon h-4 w-4" size={16} /> : null}
      {children}
      {trailing}
    </div>
  )
}

type FieldProps = InputHTMLAttributes<HTMLInputElement> & { label: string; icon?: string; hint?: string; error?: boolean; trailing?: ReactNode }

export function Field({ label, icon, hint, error, trailing, className = '', ...props }: FieldProps) {
  return (
    <label className="block">
      <span className="chenxing-label">{label}</span>
      {icon || trailing ? (
        <FieldShell icon={icon} trailing={trailing} error={error}>
          <input className={className} {...props} />
        </FieldShell>
      ) : (
        <input className={`chenxing-field ${error ? 'chenxing-field-error' : ''} ${className}`} {...props} />
      )}
      {hint ? <small className="chenxing-caption mt-1.5 block">{hint}</small> : null}
    </label>
  )
}

export function PasswordField({ label, icon, hint, error, className = '', ...props }: Omit<FieldProps, 'type' | 'trailing'>) {
  const [visible, setVisible] = useState(false)
  return (
    <Field
      label={label}
      icon={icon}
      hint={hint}
      error={error}
      className={className}
      {...props}
      type={visible ? 'text' : 'password'}
      trailing={
        <button
          type="button"
          className="chenxing-icon-btn !h-8 !w-8 shrink-0 !border-0 !bg-transparent"
          aria-label={visible ? '隐藏密码' : '显示密码'}
          onClick={() => setVisible((value) => !value)}
        >
          <Icon name={visible ? 'eye-off' : 'eye'} size={16} />
        </button>
      }
    />
  )
}

type SelectFieldProps = SelectHTMLAttributes<HTMLSelectElement> & { label: string; icon?: string }

export function SelectField({ label, icon, children, className = '', ...props }: SelectFieldProps) {
  return (
    <label className="block">
      <span className="chenxing-label">{label}</span>
      {icon ? (
        <FieldShell icon={icon}>
          <select className={className} {...props}>{children}</select>
        </FieldShell>
      ) : (
        <div className="relative">
          <select className={`chenxing-field appearance-none pr-10 ${className}`} {...props}>{children}</select>
          <Icon name="chevron-down" className="pointer-events-none absolute right-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--chenxing-muted-foreground)]" size={16} />
        </div>
      )}
    </label>
  )
}

type TextAreaFieldProps = TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; hint?: string }

export function TextAreaField({ label, hint, className = '', ...props }: TextAreaFieldProps) {
  return (
    <label className="block">
      <span className="chenxing-label">{label}</span>
      <textarea className={`chenxing-field min-h-28 resize-y ${className}`} {...props} />
      {hint ? <small className="chenxing-caption mt-1.5 block">{hint}</small> : null}
    </label>
  )
}

export function CopyValue({ value }: { value: string }) {
  return (
    <button type="button" className="cx-copy-row" onClick={() => void navigator.clipboard?.writeText(value)} title="复制">
      <span className="min-w-0 truncate">{value}</span>
      <Icon name="copy" size={15} />
    </button>
  )
}

export function PageIntro({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <p className="chenxing-mono text-[11px] uppercase tracking-[0.22em] text-[var(--chenxing-cyan)]">{eyebrow}</p>
        <h1 className="chenxing-h1 mt-2">{title}</h1>
        {description ? <p className="chenxing-caption mt-2 max-w-2xl">{description}</p> : null}
      </div>
      {action}
    </div>
  )
}

export function EmptyState({ icon = 'sparkles', title, description, action }: { icon?: string; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="cx-empty">
      <span className="inline-flex h-14 w-14 items-center justify-center rounded-2xl border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-cyan)]">
        <Icon name={icon} size={24} />
      </span>
      <strong>{title}</strong>
      {description ? <p className="chenxing-caption max-w-md">{description}</p> : null}
      {action}
    </div>
  )
}

export { logoUrl }
