import { createElement, forwardRef, useEffect, useId, useRef, useState } from 'react'
import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react'
import {
  Activity, AlertTriangle, ArrowDown, ArrowLeft, ArrowRight, ArrowUpRight, BadgeCheck, BookOpen, Box, CalendarClock, Check, ChevronDown,
  ChevronsUpDown, Circle, CircleAlert, Code2, Copy, Crown, Database, Download, ExternalLink, Eye, EyeOff, Fingerprint, Image as ImageIcon,
  FlaskConical, Gauge, Globe, Globe2, Info, KeyRound, LayoutDashboard, LayoutGrid, Layers, Link2, Lock, LockKeyhole,
  LogIn, LogOut, Mail, Menu, MoreHorizontal, Pencil, Plus, Power, Receipt, RefreshCw, Rocket, RotateCcw, Save, Search,
  Send, Server, Settings, Settings2, Shield, ShieldAlert, ShieldCheck, Sparkles, Star, Store, Terminal, Ticket, Trash2, Unlink,
  User, UserPlus, Users, Wallet, X, Zap, Clock3, type LucideIcon,
} from 'lucide-react'
import logoUrl from '../assets/logo.png'

const DEFAULT_AVATAR_URL = '/user.png'

const icons: Record<string, LucideIcon> = {
  activity: Activity, 'alert-triangle': AlertTriangle, 'arrow-down': ArrowDown, 'arrow-left': ArrowLeft, 'arrow-right': ArrowRight, 'arrow-up-right': ArrowUpRight,
  'badge-check': BadgeCheck, 'book-open': BookOpen, box: Box, 'calendar-clock': CalendarClock, check: Check,
  'chevron-down': ChevronDown, 'chevrons-up-down': ChevronsUpDown, circle: Circle, 'circle-alert': CircleAlert,
  'code-2': Code2, copy: Copy, crown: Crown, database: Database, download: Download, 'external-link': ExternalLink,
  eye: Eye, 'eye-off': EyeOff, fingerprint: Fingerprint, 'flask-conical': FlaskConical, gauge: Gauge, github: Code2, globe: Globe, 'globe-2': Globe2,
  image: ImageIcon, info: Info, 'key-round': KeyRound, 'layout-dashboard': LayoutDashboard, 'layout-grid': LayoutGrid, layers: Layers,
  link: Link2, lock: Lock, 'lock-keyhole': LockKeyhole, 'log-in': LogIn, 'log-out': LogOut, mail: Mail, menu: Menu,
  'more-horizontal': MoreHorizontal, pencil: Pencil, plus: Plus, power: Power, receipt: Receipt, 'refresh-cw': RefreshCw,
  rocket: Rocket, 'rotate-ccw': RotateCcw, save: Save, search: Search, send: Send, server: Server, settings: Settings,
  'settings-2': Settings2, shield: Shield, 'shield-alert': ShieldAlert, 'shield-check': ShieldCheck, sparkles: Sparkles,
  star: Star, store: Store, terminal: Terminal, ticket: Ticket, 'trash-2': Trash2, unlink: Unlink, user: User, 'user-plus': UserPlus,
  users: Users, wallet: Wallet, x: X, zap: Zap, 'clock-3': Clock3,
}

export function Icon({ name, size = 16, className = '', strokeWidth = 1.8 }: { name: string; size?: number; className?: string; strokeWidth?: number }) {
  const Component = icons[name] ?? Circle
  return <Component size={size} strokeWidth={strokeWidth} className={className} aria-hidden="true" />
}

export function BrandMark({ className = 'h-8 w-8 rounded-[var(--chenxing-radius-md)]', decorative = false }: { className?: string; decorative?: boolean }) {
  return <img src={logoUrl} alt={decorative ? '' : '天穹辰星'} role={decorative ? 'img' : undefined} className={className} />
}

/**
 * 头像内容：有自定义头像时渲染它，否则使用产品默认头像。
 *
 * 单独导出「内容」而不只导出容器，是因为顶栏的头像本身就是一个菜单触发按钮，
 * 容器必须由调用方持有。两处若各自判断「有没有头像」，回落规则迟早会分叉。
 *
 * 图片是纯装饰：相邻文本已经给出用户名，`alt=""` 让屏幕阅读器跳过它，
 * 避免把同一个信息读两遍（WCAG 2.1 SC 1.1.1 的装饰性图像约定）。
 */
export function AvatarContent({ src }: { src?: string; name?: string | null }) {
  return <img src={src || DEFAULT_AVATAR_URL} alt="" className="chenxing-avatar-image" draggable={false} />
}

/** 非交互场景的头像容器。交互场景（菜单触发器、上传入口）自持容器并内嵌 `AvatarContent`。 */
export function Avatar({ src, name, className = '' }: { src?: string; name?: string | null; className?: string }) {
  return (
    <span className={`chenxing-avatar ${className}`}>
      <AvatarContent src={src} name={name} />
    </span>
  )
}

export function BrandLockup({ subtitle = '辰星认证中枢', compact = false }: { subtitle?: string; compact?: boolean }) {
  return (
    <span className="flex items-center gap-2.5">
      <BrandMark decorative className={compact ? 'chenxing-brand-logo' : 'h-8 w-8 rounded-[var(--chenxing-radius-md)]'} />
      <span className={compact ? undefined : 'hidden sm:block'}>
        <span className={compact ? 'chenxing-wordmark text-aurora block text-base' : 'chenxing-body block text-sm font-semibold leading-tight'}>天穹辰星</span>
        <span className={compact ? 'chenxing-mono block text-[9px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]' : 'chenxing-caption block text-[10px] leading-tight tracking-[0.08em]'}>{subtitle}</span>
      </span>
    </span>
  )
}

/** 玻璃容器允许的根元素：默认 div，语义场景按无障碍需要选择对应标签 */
type HudPanelElement = 'div' | 'section' | 'article' | 'aside' | 'form'

type HudPanelProps = HTMLAttributes<HTMLElement> & {
  /** 渲染成哪种标签。页面需要语义标签时传 section / article / aside / form，不要自己写玻璃容器类 */
  as?: HudPanelElement
  children: ReactNode
}

/**
 * 玻璃容器唯一入口：`.chenxing-hud-panel` 的类名契约只在这里出现一次。
 * 页面不得直接写该类名，否则容器结构变更时无法统一跟随。
 */
export const HudPanel = forwardRef<HTMLElement, HudPanelProps>(function HudPanel({ as = 'div', children, className = '', ...rest }, ref) {
  // 用 createElement 承载多态标签，ref 始终指向唯一的实际面板容器。
  return createElement(as, { ref, className: `chenxing-hud-panel ${className}`, ...rest }, children)
})

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'ghost' | 'danger'
  icon?: string
}

export function Button({ variant = 'primary', icon, children, className = '', ...props }: ButtonProps) {
  /* aria-disabled="true" 表示「禁用但保持可聚焦」：键盘和屏幕阅读器仍能到达按钮
     并读出 aria-describedby 关联的禁用原因，但点击与提交必须被拦住。
     依据 WCAG 2.1 SC 1.3.1 / 4.1.2：状态要能被辅助技术获取，不只靠视觉变淡。
     拦点击必须同时 stopPropagation：原生 disabled 按钮不派发 click、不冒泡，
     而 aria-disabled 按钮的 click（鼠标点击或键盘 Enter/Space 激活）照常冒泡，
     只 preventDefault 拦不住父级（可点击卡片、行）的 onClick，禁用态会误触发父级动作。 */
  const inert = props['aria-disabled'] === true || props['aria-disabled'] === 'true'
  return (
    <button
      type="button"
      className={`chenxing-btn-${variant} ${className}`}
      {...props}
      onClick={inert ? (event) => { event.preventDefault(); event.stopPropagation() } : props.onClick}
    >
      {icon ? <Icon name={icon} size={16} /> : null}
      {children}
    </button>
  )
}

export function Badge({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'success' | 'warning' | 'gold' }) {
  const cls = tone === 'success' ? 'chenxing-badge-success' : tone === 'warning' ? 'chenxing-badge-warning' : tone === 'gold' ? 'chenxing-badge-gold' : 'chenxing-badge'
  return <span className={cls}>{children}</span>
}

export function Chip({ children, onRemove }: { children: ReactNode; onRemove?: () => void }) {
  return (
    <span className="chenxing-chip">
      {children}
      {onRemove ? (
        /* 视觉上仍是紧凑的 12px 图标，但命中区保证 24x24（WCAG 2.5.8）：
           负外边距让 24px 按钮从 chip 的内容盒向外扩展，不撑大 chip 本体。 */
        <button
          type="button"
          className="-my-1 -mr-2 ml-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[var(--chenxing-cyan)] transition-colors hover:bg-[var(--chenxing-muted)]"
          onClick={onRemove}
          aria-label="移除"
        >
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
  const role = tone === 'warning' ? 'alert' : 'status'
  const live = tone === 'warning' ? 'assertive' : 'polite'
  return (
    <div className={`cx-alert cx-alert-${tone}`} role={role} aria-live={live}>
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

type FieldProps = InputHTMLAttributes<HTMLInputElement> & {
  label: string
  icon?: string
  hint?: string
  error?: boolean
  /** 校验失败文案。传入即视为 error 状态，并接管 aria-invalid / aria-describedby。 */
  errorText?: string
  trailing?: ReactNode
}

export function Field({ label, icon, hint, error, errorText, trailing, className = '', ...props }: FieldProps) {
  const autoId = useId()
  const inputId = props.id ?? autoId
  const messageId = `${inputId}-message`
  const invalid = Boolean(errorText) || error
  /* label 与 input 用 htmlFor 显式关联，提示和校验文案留在 label 之外：
     包在 label 里会被算进无障碍名称，控件会被读成「用户名 3-64 个字符…」，
     再经 aria-describedby 重复一遍。名称只留标签，说明走 describedby。
     依据 WCAG 2.1 SC 3.3.2（标签或说明）与 SC 3.3.1（错误标识）。 */
  const describedBy = [props['aria-describedby'], errorText || hint ? messageId : undefined]
    .filter(Boolean).join(' ') || undefined
  const inputProps = { ...props, id: inputId, 'aria-describedby': describedBy, 'aria-invalid': invalid || undefined }
  return (
    <div>
      <label className="chenxing-label" htmlFor={inputId}>{label}</label>
      {icon || trailing ? (
        <FieldShell icon={icon} trailing={trailing} error={invalid}>
          <input className={className} {...inputProps} />
        </FieldShell>
      ) : (
        <input className={`chenxing-field ${invalid ? 'chenxing-field-error' : ''} ${className}`} {...inputProps} />
      )}
      {errorText ? (
        <small className="chenxing-field-message" id={messageId}>
          <Icon name="circle-alert" size={13} className="shrink-0" />
          {errorText}
        </small>
      ) : hint ? (
        <small className="chenxing-caption mt-1.5 block" id={messageId}>{hint}</small>
      ) : null}
    </div>
  )
}

export function PasswordField({ label, icon, hint, error, errorText, autoComplete = 'new-password', className = '', ...props }: Omit<FieldProps, 'type' | 'trailing'>) {
  const [visible, setVisible] = useState(false)
  return (
    <Field
      label={label}
      icon={icon}
      hint={hint}
      error={error}
      errorText={errorText}
      className={className}
      {...props}
      autoComplete={autoComplete}
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

type TextAreaFieldProps = TextareaHTMLAttributes<HTMLTextAreaElement> & {
  label: string
  hint?: string
  error?: boolean
  errorText?: string
}

export function TextAreaField({ label, hint, error, errorText, className = '', ...props }: TextAreaFieldProps) {
  const autoId = useId()
  const inputId = props.id ?? autoId
  const messageId = `${inputId}-message`
  const invalid = Boolean(errorText) || error
  // 与 Field 同一套关联方式：提示不进无障碍名称，只作为 describedby 说明。
  const describedBy = [props['aria-describedby'], errorText || hint ? messageId : undefined].filter(Boolean).join(' ') || undefined
  return (
    <div>
      <label className="chenxing-label" htmlFor={inputId}>{label}</label>
      <textarea
        className={`chenxing-field min-h-28 resize-y ${invalid ? 'chenxing-field-error' : ''} ${className}`}
        {...props}
        id={inputId}
        aria-describedby={describedBy}
        aria-invalid={invalid || undefined}
      />
      {errorText ? (
        <small className="chenxing-field-message" id={messageId}>
          <Icon name="circle-alert" size={13} className="shrink-0" />
          {errorText}
        </small>
      ) : hint ? (
        <small className="chenxing-caption mt-1.5 block" id={messageId}>{hint}</small>
      ) : null}
    </div>
  )
}

type CopyValueProps = {
  value: string
  /** 覆盖默认复制操作名称；开启 announceValue 后，完整值会追加到该名称。 */
  ariaLabel?: string
  /** 仅在确实需要时把完整值加入无障碍名称，例如手动输入 TOTP 密钥。 */
  announceValue?: boolean
}

type CopyStatus = 'idle' | 'copied' | 'failed'

/**
 * 把文本复制进剪贴板，永不抛出，用返回值告知调用方是否成功。
 *
 * 优先使用异步剪贴板 API（仅安全上下文可用）；API 缺失、权限被拒或文档未聚焦时，
 * 回退到隐藏 textarea + execCommand('copy')——它只依赖用户手势，不依赖权限。
 * 两种途径都失败才返回 false，由组件显式反馈，绝不静默丢弃。
 */
async function copyTextToClipboard(value: string): Promise<boolean> {
  if (navigator.clipboard && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      // 权限被拒等场景：继续尝试 execCommand 回退，而不是直接放弃
    }
  }
  const textarea = document.createElement('textarea')
  textarea.value = value
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.top = '0'
  textarea.style.left = '-9999px'
  textarea.style.opacity = '0'
  document.body.appendChild(textarea)
  const selection = window.getSelection()
  const previousRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null
  textarea.select()
  let ok = false
  try {
    ok = document.execCommand('copy')
  } catch {
    ok = false
  } finally {
    textarea.remove()
    if (selection && previousRange) {
      selection.removeAllRanges()
      selection.addRange(previousRange)
    }
  }
  return ok
}

export function CopyValue({ value, ariaLabel, announceValue = false }: CopyValueProps) {
  const [status, setStatus] = useState<CopyStatus>('idle')
  const resetTimerRef = useRef<number | null>(null)
  const accessibleName = announceValue
    ? `${ariaLabel ?? '复制值'}：${value}`
    : ariaLabel ?? '复制值'
  const statusText = status === 'copied' ? '已复制' : status === 'failed' ? '复制失败' : ''

  useEffect(() => () => {
    if (resetTimerRef.current !== null) window.clearTimeout(resetTimerRef.current)
  }, [])

  async function handleCopy() {
    const ok = await copyTextToClipboard(value)
    if (resetTimerRef.current !== null) window.clearTimeout(resetTimerRef.current)
    resetTimerRef.current = null
    setStatus(ok ? 'copied' : 'failed')
    if (ok) {
      // 成功反馈短暂展示后恢复常态；失败状态保留到下一次点击，
      // 避免一次性凭据（Client Secret / TOTP 密钥）被误以为已复制。
      resetTimerRef.current = window.setTimeout(() => setStatus('idle'), 1600)
    }
  }

  return (
    <button
      type="button"
      className="cx-copy-row"
      onClick={() => void handleCopy()}
      title={statusText || '复制'}
      aria-label={accessibleName}
    >
      <span className="min-w-0 truncate">{value}</span>
      <span className="flex shrink-0 items-center gap-1.5">
        {statusText ? (
          <span
            className={`chenxing-caption ${status === 'copied' ? 'text-[var(--chenxing-success)]' : 'text-[var(--chenxing-error)]'}`}
            aria-live="polite"
          >
            {statusText}
          </span>
        ) : null}
        <Icon name={status === 'copied' ? 'check' : status === 'failed' ? 'alert-triangle' : 'copy'} size={15} />
      </span>
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
