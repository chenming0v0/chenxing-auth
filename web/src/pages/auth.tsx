import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { apiFetch, externalLoginErrorMessage, type LoginResponse, type PendingLoginResponse } from '../api'
import { AuthPanel, AuthShell } from '../components/shells'
import { Button, Field, HudPanel, Icon, Notice, PasswordField } from '../components/ui'
import { FactorOrchestrator } from './auth/factor-orchestrator'
import { ExternalProviders } from './auth/external-providers'

type AuthMode = 'login' | 'register'

function safeReturnTo(value: string | null): string {
  if (!value) return '/console'
  try {
    const decoded = decodeURIComponent(value)
    return decoded.startsWith('/') && !decoded.startsWith('//') ? decoded : '/console'
  } catch {
    return '/console'
  }
}

export function AuthPage({ mode }: { mode: AuthMode }) {
  const navigate = useNavigate()
  const location = useLocation()
  const { refresh, clear } = useAuth()
  const query = new URLSearchParams(location.search)
  const requestId = query.get('request_id')
  const returnTo = safeReturnTo(query.get('returnTo'))
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  // Issue #89：服务条款同意必须是用户主动的肯定性行为，初始值不得预勾选。
  const [agree, setAgree] = useState(false)
  const [authTab, setAuthTab] = useState<'account' | 'auth'>('account')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<PendingLoginResponse | null>(null)
  const isLogin = mode === 'login'
  const externalError = query.get('external_error')

  async function completeLogin() {
    const profile = await refresh()
    if (!profile) {
      setMessage('登录未完成，请重新尝试。')
      return
    }
    if (requestId) {
      try {
        await apiFetch<void>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}/bind`, { method: 'POST' })
      } catch (error) {
        clear()
        setMessage(error instanceof Error ? error.message : '授权请求绑定失败，请重新开始。')
        return
      }
      navigate(`/oauth/consent?request_id=${encodeURIComponent(requestId)}`)
      return
    }
    navigate(returnTo)
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    if (!email || !password || (!isLogin && !username)) {
      setMessage('请完整填写必填信息。')
      return
    }
    if (password.length < 10) {
      setMessage('密码至少需要 10 位字符。')
      return
    }
    if (!isLogin && !agree) {
      setMessage('请先同意服务条款与隐私政策。')
      return
    }
    setBusy(true)
    try {
      if (!isLogin) {
        await apiFetch<{ user: unknown }>('/api/v1/users', {
          method: 'POST',
          redirectOn401: false,
          body: JSON.stringify({ username, email, password, display_name: displayName || null }),
        })
        navigate('/login?registered=1')
        return
      }
      const response = await apiFetch<LoginResponse | PendingLoginResponse>('/api/v1/auth/login', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ identifier: email, password }),
      })
      if ('status' in response && 'methods' in response) {
        setPending(response)
        return
      }
      await completeLogin()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '登录未完成，请稍后重试。')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell
      status={isLogin ? '统一登录' : '创建通行证'}
      action={isLogin ? '创建通行证' : '登录'}
      actionTo={isLogin ? '/register' : '/login'}
    >
      <AuthPanel>
        <div className="flex items-center justify-between">
          <div>
            <h2 className="chenxing-h2">{isLogin ? '统一登录' : '创建辰星通行证'}</h2>
            <p className="chenxing-caption mt-1">{isLogin ? '使用辰星通行证身份进入服务' : '铸造你的辰星信标'}</p>
          </div>
        </div>

        {isLogin ? (
          <div className="cx-auth-tabs mt-6">
            <button type="button" className={`cx-auth-tab${authTab === 'account' ? ' is-active' : ''}`} onClick={() => setAuthTab('account')}>账号登录</button>
            <button type="button" className={`cx-auth-tab${authTab === 'auth' ? ' is-active' : ''}`} onClick={() => setAuthTab('auth')}>Auth 登录</button>
          </div>
        ) : null}

        {query.get('registered') ? <div className="mt-5"><Notice tone="success">注册成功，请使用新账号登录。</Notice></div> : null}
        {externalError ? <div className="mt-5"><Notice tone="warning">{externalLoginErrorMessage(externalError)}</Notice></div> : null}
        {message ? <div className="mt-5"><Notice tone="warning">{message}</Notice></div> : null}

        {pending ? (
          <div className="mt-5">
            <FactorOrchestrator pending={pending} busy={busy} onComplete={completeLogin} onBusy={setBusy} onMessage={setMessage} />
          </div>
        ) : isLogin && authTab === 'auth' ? (
          <div className="mt-5">
            <ExternalProviders requestId={requestId} />
          </div>
        ) : (
          <form className="mt-5 space-y-4" onSubmit={submit} noValidate>
            {!isLogin ? (
              <Field label="昵称" icon="user" placeholder="你的星际代号" autoComplete="nickname" value={displayName || username} onChange={(event) => { setDisplayName(event.target.value); if (!username) setUsername(event.target.value) }} />
            ) : null}
            {!isLogin ? (
              <Field label="用户名" icon="user" placeholder="chenxing_user" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />
            ) : null}
            <Field
              label={isLogin ? '邮箱或用户名' : '邮箱'}
              icon="mail"
              type={isLogin ? 'text' : 'email'}
              placeholder={isLogin ? 'you@chenxing.star' : 'you@chenxing.star'}
              autoComplete="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
            <PasswordField
              label="密码"
              icon="lock-keyhole"
              placeholder={isLogin ? '输入通行凭证' : '至少 10 位'}
              autoComplete={isLogin ? 'current-password' : 'new-password'}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            {!isLogin ? (
              <label className="flex cursor-pointer items-start gap-2 text-[0.8125rem] leading-relaxed text-[var(--chenxing-muted-foreground)]">
                <input type="checkbox" checked={agree} onChange={(event) => setAgree(event.target.checked)} className="mt-1 h-4 w-4 rounded accent-[var(--chenxing-primary)]" />
                <span>我已阅读并同意《辰星通行证服务条款》与《隐私政策》</span>
              </label>
            ) : (
              // Issue #88：后端 LoginInput 只接受 identifier / password / totp_code，
              // 没有 keep_login 字段，会话有效期完全由服务端配置决定。
              // 「在此设备保持登录」复选框对实际行为零影响，属于误导性 UI，故移除。
              <div className="flex items-center justify-end">
                <a className="chenxing-link" href="#">忘记密码？</a>
              </div>
            )}
            {/* 未同意条款时禁用提交按钮，避免出现「无同意记录却完成注册」的情况 */}
            <Button type="submit" variant="primary" className="w-full py-3" disabled={busy || (!isLogin && !agree)}>
              {busy ? '处理中…' : isLogin ? '登录 · 进入星门' : '创建通行证'}
              <Icon name="arrow-right" size={16} />
            </Button>
          </form>
        )}

        {!pending ? (
          <p className="chenxing-caption mt-6 text-center">
            {isLogin ? '还没有通行证？' : '已有通行证？'}
            <Link to={isLogin ? '/register' : '/login'} className="chenxing-link ml-1 font-medium">
              {isLogin ? '创建辰星通行证' : '直接登录'}
            </Link>
          </p>
        ) : null}
      </AuthPanel>
    </AuthShell>
  )
}


export function BootstrapPage() {
  const navigate = useNavigate()
  const { refreshBootstrap } = useAuth()
  const [done, setDone] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setBusy(true)
    try {
      await apiFetch('/api/v1/admin/bootstrap', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ username, email, password }),
      })
      await refreshBootstrap()
      setDone(true)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '初始化未完成，请稍后重试。')
    } finally {
      setBusy(false)
    }
  }

  return (
    <AuthShell status="系统初始化" action="返回登录" actionTo="/login" className="">
      <section className="relative z-10 flex min-h-screen items-center justify-center px-6 py-14">
        <div className="w-full max-w-lg">
          <HudPanel>
            <div className="text-center">
              <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">// System Not Initialized</p>
              <h1 className="chenxing-h1 mt-3">点亮首座星门</h1>
              <p className="chenxing-caption mt-2">创建唯一的 Owner 账户（ID 固定为 1）。此操作仅允许执行一次，并发请求由数据库 advisory lock 保证最多成功一次。</p>
            </div>
            <div className="mt-6 space-y-2.5">
              {[
                ['database', 'PostgreSQL 迁移与连接'],
                ['zap', 'Redis 短期状态层'],
                ['key-round', 'JWK 密钥环初始化'],
              ].map(([icon, label]) => (
                <div key={label} className="flex items-center justify-between rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] px-4 py-3">
                  <span className="flex items-center gap-2.5">
                    <Icon name={icon} className="h-4 w-4 text-[var(--chenxing-cyan)]" size={16} />
                    <span className="chenxing-caption text-[var(--chenxing-foreground)]">{label}</span>
                  </span>
                  <span className="chenxing-badge-success"><Icon name="check" size={12} />READY</span>
                </div>
              ))}
            </div>
            {message ? <div className="mt-5"><Notice tone="warning">{message}</Notice></div> : null}
            {done ? (
              <div className="mt-6 space-y-4">
                <Notice tone="success">Owner 初始化成功，请使用新账号登录。</Notice>
                <Button type="button" className="w-full py-3" icon="log-in" onClick={() => navigate('/login')}>前往登录</Button>
              </div>
            ) : (
              <form className="mt-6 space-y-4" onSubmit={submit} noValidate>
                <Field label="管理员用户名" icon="user" placeholder="owner" value={username} onChange={(event) => setUsername(event.target.value)} required />
                <Field label="邮箱" icon="mail" type="email" placeholder="owner@chenxing.star" value={email} onChange={(event) => setEmail(event.target.value)} required />
                <PasswordField label="密码" icon="lock-keyhole" placeholder="至少 12 位，含字母与数字" value={password} onChange={(event) => setPassword(event.target.value)} required />
                <div className="flex items-start gap-3 rounded-[var(--chenxing-radius-md)] border border-[rgba(255,107,122,0.35)] bg-[rgba(255,107,122,0.08)] px-4 py-3">
                  <Icon name="alert-triangle" className="mt-0.5 h-4 w-4 shrink-0 text-[var(--chenxing-error)]" size={16} />
                  <p className="chenxing-caption text-[var(--chenxing-foreground)]">初始化成功后将跳转至统一登录页，不会自动创建会话。需要重新初始化时，请由维护人员清理数据库后重试。</p>
                </div>
                <Button type="submit" className="w-full py-3" disabled={busy}>
                  {busy ? '初始化中…' : '初始化并创建 Owner'}
                  <Icon name="arrow-right" size={16} />
                </Button>
              </form>
            )}
          </HudPanel>
          <p className="chenxing-mono mt-6 text-center text-[10px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]">First Light Sequence · 天穹辰星</p>
        </div>
      </section>
    </AuthShell>
  )
}
