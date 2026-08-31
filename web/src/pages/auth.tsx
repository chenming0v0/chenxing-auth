import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { apiFetch, bindAuthorizationRequest, externalLoginErrorMessage, type LoginResponse, type PendingLoginResponse, type RegistrationStatus } from '../api'
import { AuthPanel, AuthShell } from '../components/shells'
import { Button, Field, HudPanel, Icon, Notice, PasswordField } from '@chenxing/ui'
import { FactorOrchestrator } from './auth/factor-orchestrator'
import { ExternalProviders } from './auth/external-providers'
import { passkeyErrorMessage, supportsWebAuthnGet } from '../passkey'
import { loginWithDiscoverablePasskey } from './auth/passkey-login'
import { authModeTarget, dropDeadRequestId, safeReturnTo } from './auth/navigation'

export { safeReturnTo } from './auth/navigation'

type AuthMode = 'login' | 'register'

const PASSWORD_MIN_LENGTH = 10
const PASSWORD_MAX_LENGTH = 128
// HTML maxLength counts UTF-16 code units; two units per code point is the safe upper bound.
const PASSWORD_MAX_INPUT_LENGTH = PASSWORD_MAX_LENGTH * 2

function passwordCodePointLength(value: string): number {
  return Array.from(value).length
}
function limitPasswordInput(value: string): string {
  return Array.from(value).slice(0, PASSWORD_MAX_LENGTH).join('')
}

export function AuthPage({ mode }: { mode: AuthMode }) {
  const navigate = useNavigate()
  const location = useLocation()
  const { refresh } = useAuth()
  const query = new URLSearchParams(location.search)
  const requestId = query.get('request_id')
  const returnTo = safeReturnTo(query.get('returnTo'))
  /* #685：登录 ⇄ 注册的切换必须带走待授权上下文，否则用户中途改走注册流程后
     requestId 丢失，注册完成回到登录页时不再绑定原授权请求，最终落到 /console，
     第三方授权流程静默断链。只透传白名单里的 request_id 与 returnTo。 */
  const modeSwitchTo = authModeTarget(mode === 'login' ? '/register' : '/login', query)
  const registeredLoginTo = authModeTarget('/login', query, { registered: '1' })
  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [invitationCode, setInvitationCode] = useState('')
  // Issue #89：服务条款同意必须是用户主动的肯定性行为，初始值不得预勾选。
  const [agree, setAgree] = useState(false)
  const [authTab, setAuthTab] = useState<'account' | 'auth'>('account')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<PendingLoginResponse | null>(null)
  // 绑定失败后置位，渲染「进入控制台」出口：会话仍然有效，登录页不再是死路。
  const [bindFailed, setBindFailed] = useState(false)
  // 公开注册状态（仅注册模式拉取）：null = 未取回或取回失败，保持现状由后端兜底。
  const [registrationStatus, setRegistrationStatus] = useState<RegistrationStatus | null>(null)
  // busy updates after React render; the ref closes the same-event submit window.
  const submitLockRef = useRef(false)
  const isLogin = mode === 'login'
  const externalError = query.get('external_error')

  useEffect(() => {
    if (mode === 'login') return
    let active = true
    apiFetch<RegistrationStatus>('/api/v1/auth/registration-status', { redirectOn401: false })
      .then((value) => {
        // 形状不合法时视同取回失败：不阻塞表单，提交时由后端给出权威结果。
        if (active
          && typeof value.enabled === 'boolean'
          && typeof value.email_verification_required === 'boolean') {
          setRegistrationStatus(value)
        }
      })
      .catch(() => { /* 取回失败不阻塞注册表单，由后端在提交时兜底。 */ })
    return () => { active = false }
  }, [mode])

  /* 注册页如实状态：enabled 已是服务端计入 Issuer 闸门后的有效值；
     邮箱验证投递能力在建，要求验证期间注册同样不可用。 */
  const registrationBlockedMessage = isLogin || registrationStatus === null
    ? null
    : !registrationStatus.enabled
      ? '自助注册未开放，请联系管理员创建账号。'
      : registrationStatus.email_verification_required
        ? '平台要求邮箱所有权验证，验证投递能力在建，注册暂不可用。'
        : null

  function acquireSubmitLock(): boolean {
    if (submitLockRef.current) return false
    submitLockRef.current = true
    return true
  }

  function releaseSubmitLock() {
    submitLockRef.current = false
    setBusy(false)
  }

  /** MFA 子步骤也使用同一把同步锁，避免 busy 尚未重渲染时重复发起请求。 */
  function setAuthBusy(nextBusy: boolean): boolean {
    if (!nextBusy) {
      releaseSubmitLock()
      return true
    }
    if (!acquireSubmitLock()) return false
    setBusy(true)
    return true
  }

  async function completeLogin() {
    const profile = await refresh()
    if (!profile) {
      setMessage('登录未完成，请重新尝试。')
      return
    }
    if (requestId) {
      try {
        await bindAuthorizationRequest(requestId)
      } catch (error) {
        // 登录本身已经成功，绑定失败只说明这条授权请求不可用（已过期、
        // 不是本浏览器发起、或正被并发更新）。此处**不得**清除会话（#270）：
        // 清了会把用户打回未认证态，登录页再次把他送去授权流程，形成
        // 「登录成功 → 绑定失败 → 视为未登录 → 再登录」的 401 循环。
        // Issue #395：失效的 request_id 若残留，用户重新登录后仍会绑定同一
        // 失效请求、再次失败，陷入无出口循环。绑定失败即作废本条授权请求：
        // 从地址栏与 returnTo 里清除它、复位停留在失效 MFA 步骤上的 pending，
        // 并在文案旁给出「进入控制台」出口——会话仍然有效，用户随时可以离开。
        setMessage(error instanceof Error ? error.message : '授权请求绑定失败，请重新开始。')
        setBindFailed(true)
        setPending(null)
        dropDeadRequestId(requestId)
        return
      }
      navigate(`/oauth/consent?request_id=${encodeURIComponent(requestId)}`)
      return
    }
    navigate(returnTo)
  }

  /** login_ticket 失效时卸载因子状态，并回到账号表单提供明确恢复出口（#385）。 */
  function resetToLogin() {
    releaseSubmitLock()
    setMessage('验证流程已失效，请重新登录。')
    setPending(null)
    setAuthTab('account')
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!acquireSubmitLock()) return
    try {
      setMessage('')
      setBindFailed(false)
      // fieldset/按钮禁用之外的兜底：注册被平台状态关闭时不发出注册请求。
      if (!isLogin && registrationBlockedMessage) {
        setMessage(registrationBlockedMessage)
        return
      }
      if (!email || !password || (!isLogin && !username)) {
        setMessage('请完整填写必填信息。')
        return
      }
      if (!isLogin) {
        const passwordLength = passwordCodePointLength(password)
        if (passwordLength < PASSWORD_MIN_LENGTH) {
          setMessage(`密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`)
          return
        }
        if (passwordLength > PASSWORD_MAX_LENGTH) {
          setMessage(`密码不能超过 ${PASSWORD_MAX_LENGTH} 个字符。`)
          return
        }
      }
      if (!isLogin && !agree) {
        setMessage('请先同意服务条款与隐私政策。')
        return
      }
      setBusy(true)
      if (!isLogin) {
        await apiFetch<{ user: unknown }>('/api/v1/users', {
          method: 'POST',
          redirectOn401: false,
          csrf: 'pre-session',
          body: JSON.stringify({
            username,
            email,
            password,
            display_name: displayName || null,
            invitation_code: registrationStatus?.invitation_code_required ? invitationCode : null,
          }),
        })
        navigate(registeredLoginTo)
        return
      }
      const response = await apiFetch<LoginResponse | PendingLoginResponse>('/api/v1/auth/login', {
        method: 'POST',
        redirectOn401: false,
        csrf: 'pre-session',
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
      releaseSubmitLock()
    }
  }

  async function loginWithPasskey(): Promise<void> {
    if (!isLogin || !supportsWebAuthnGet() || !acquireSubmitLock()) {
      if (!supportsWebAuthnGet()) setMessage('当前浏览器不支持 Passkey，请使用支持 WebAuthn 的浏览器。')
      return
    }
    try {
      setMessage('')
      setBusy(true)
      await loginWithDiscoverablePasskey(setPending, completeLogin)
    } catch (error) {
      setMessage(passkeyErrorMessage(error))
    } finally {
      releaseSubmitLock()
    }
  }

  return (
    <AuthShell
      status={isLogin ? '统一登录' : '创建通行证'}
      action={isLogin ? '创建通行证' : '登录'}
      actionTo={modeSwitchTo}
    >
      <AuthPanel>
        <div className="flex items-center justify-between">
          <div>
            {/* 语义层级为页面唯一 h1；视觉沿用 chenxing-h2 面板标题样式，保持既有视觉层级不变 */}
            <h1 className="chenxing-h2">{isLogin ? '统一登录' : '创建辰星通行证'}</h1>
            <p className="chenxing-caption mt-1">{isLogin ? '使用辰星通行证身份进入服务' : '铸造你的辰星信标'}</p>
          </div>
        </div>

        {isLogin ? (
          <div className="cx-auth-tabs mt-6">
            <button type="button" className={`cx-auth-tab${authTab === 'account' ? ' is-active' : ''}`} aria-pressed={authTab === 'account'} onClick={() => setAuthTab('account')}>账号登录</button>
            <button type="button" className={`cx-auth-tab${authTab === 'auth' ? ' is-active' : ''}`} aria-pressed={authTab === 'auth'} onClick={() => setAuthTab('auth')}>Auth 登录</button>
          </div>
        ) : null}

        {query.get('registered') === '1' ? <div className="mt-5"><Notice tone="success">注册成功，请使用新账号登录。</Notice></div> : null}
        {query.get('logout') === 'failed' ? (
          <div className="mt-5">
            <Notice tone="warning">未能完全登出：服务端会话撤销失败，本设备的登录状态可能仍然有效。请刷新页面后重新退出，或在浏览器中清除本站点 Cookie。</Notice>
          </div>
        ) : null}
        {externalError ? <div className="mt-5"><Notice tone="warning">{externalLoginErrorMessage(externalError)}</Notice></div> : null}
        {registrationBlockedMessage ? <div className="mt-5"><Notice tone="warning">{registrationBlockedMessage}</Notice></div> : null}
        {message ? <div className="mt-5"><Notice tone="warning">{message}</Notice></div> : null}
        {bindFailed ? (
          <div className="mt-3">
            <Button type="button" icon="layout-dashboard" className="w-full py-3" onClick={() => navigate('/console')}>
              进入控制台
            </Button>
          </div>
        ) : null}

        {pending ? (
          <div className="mt-5">
            <FactorOrchestrator pending={pending} busy={busy} onComplete={completeLogin} onPending={setPending} onBusy={setAuthBusy} onMessage={setMessage} onRelogin={resetToLogin} />
          </div>
        ) : isLogin && authTab === 'auth' ? (
          <div className="mt-5 space-y-5">
            <Button type="button" variant="primary" icon="key-round" className="w-full py-3" onClick={() => void loginWithPasskey()} disabled={busy}>
              {busy ? '验证中…' : '使用 Passkey 登录'}
            </Button>
            <div className="flex items-center gap-3 text-[11px] uppercase tracking-[0.16em] text-[var(--chenxing-muted-foreground)]"><span className="h-px flex-1 bg-[var(--chenxing-border)]" /><span>外部身份源</span><span className="h-px flex-1 bg-[var(--chenxing-border)]" /></div>
            <ExternalProviders requestId={requestId} />
          </div>
        ) : (
          <form className="mt-5 space-y-4" onSubmit={submit} noValidate>
            {/* 注册被平台状态关闭时整表禁用（fieldset disabled 模式）；
                display:contents 保持既有 space-y 布局，间距由 fieldset 自身承接。
                登录模式不受影响：disabled 恒为 false。 */}
            <fieldset disabled={!isLogin && (busy || registrationBlockedMessage !== null)} className="contents space-y-4">
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
                placeholder={isLogin ? '输入通行凭证' : `${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个字符`}
                autoComplete={isLogin ? 'current-password' : 'new-password'}
                value={password}
                onChange={(event) => setPassword(isLogin ? event.target.value : limitPasswordInput(event.target.value))}
                maxLength={!isLogin ? PASSWORD_MAX_INPUT_LENGTH : undefined}
                hint={!isLogin ? `长度为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个 Unicode 字符。` : undefined}
              />
              {!isLogin && registrationStatus?.invitation_code_required ? (
                <Field
                  label="邀请码"
                  icon="ticket"
                  placeholder="输入管理员提供的邀请码"
                  autoComplete="off"
                  value={invitationCode}
                  onChange={(event) => setInvitationCode(event.target.value)}
                  required
                />
              ) : null}
              {!isLogin ? (
                <label className="flex cursor-pointer items-start gap-2 text-[0.8125rem] leading-relaxed text-[var(--chenxing-muted-foreground)]">
                  <input type="checkbox" checked={agree} onChange={(event) => setAgree(event.target.checked)} className="mt-1 h-4 w-4 rounded accent-[var(--chenxing-primary)]" />
                  <span>我已阅读并同意《辰星通行证服务条款》与《隐私政策》</span>
                </label>
              ) : (
                // Issue #88：后端 LoginInput 只接受 identifier / password / totp_code，
                // 没有 keep_login 字段，会话有效期完全由服务端配置决定。
                // 「在此设备保持登录」复选框对实际行为零影响，属于误导性 UI，故移除。
                // Issue #240：后端没有自助重置密码流程，不渲染指向 # 的伪链接；
                // 初始密码由管理员创建用户时设置，改为联系管理员的静态引导。
                <div className="flex items-center justify-end">
                  <span className="chenxing-caption text-[12.5px] text-[var(--chenxing-muted-foreground)]">忘记密码？请联系管理员重置。</span>
                </div>
              )}
              {/* 未同意条款或注册被平台状态关闭时禁用提交按钮，避免出现「无同意记录却完成注册」的情况 */}
              <Button type="submit" variant="primary" className="w-full py-3" disabled={busy || (!isLogin && (!agree || registrationBlockedMessage !== null))}>
                {busy ? '处理中…' : isLogin ? '登录 · 进入星门' : '创建通行证'}
                <Icon name="arrow-right" size={16} />
              </Button>
            </fieldset>
          </form>
        )}

        {!pending ? (
          <p className="chenxing-caption mt-6 text-center">
            {isLogin ? '还没有通行证？' : '已有通行证？'}
            <Link to={modeSwitchTo} className="chenxing-link ml-1 font-medium">
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
  const { completeBootstrap } = useAuth()
  const [done, setDone] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  // busy 要等 React 渲染后才生效，ref 在同一个事件循环内同步关闭重复提交窗口（#397）。
  const submitLockRef = useRef(false)
  const [username, setUsername] = useState('')

  function acquireSubmitLock(): boolean {
    if (submitLockRef.current) return false
    submitLockRef.current = true
    return true
  }

  function releaseSubmitLock() {
    submitLockRef.current = false
    setBusy(false)
  }
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!acquireSubmitLock()) return
    try {
      setMessage('')
      const passwordLength = passwordCodePointLength(password)
      if (passwordLength < PASSWORD_MIN_LENGTH) {
        setMessage(`密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`)
        return
      }
      if (passwordLength > PASSWORD_MAX_LENGTH) {
        setMessage(`密码不能超过 ${PASSWORD_MAX_LENGTH} 个字符。`)
        return
      }
      setBusy(true)
      await apiFetch('/api/v1/admin/bootstrap', {
        method: 'POST',
        redirectOn401: false,
        csrf: 'pre-session',
        body: JSON.stringify({ username, email, password }),
      })
      setDone(true)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '初始化未完成，请稍后重试。')
    } finally {
      releaseSubmitLock()
    }
  }

  return (
    <AuthShell status="系统初始化" action="返回登录" actionTo="/login" className="">
      <section className="relative z-[var(--chenxing-z-content)] flex min-h-screen items-center justify-center px-6 py-14">
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
                <Button
                  type="button"
                  className="w-full py-3"
                  icon="log-in"
                  onClick={() => {
                    completeBootstrap()
                    navigate('/login')
                  }}
                >
                  前往登录
                </Button>
              </div>
            ) : (
              <form className="mt-6 space-y-4" onSubmit={submit} noValidate>
                <Field label="管理员用户名" icon="user" placeholder="chenxing-owner" value={username} onChange={(event) => setUsername(event.target.value)} required />
                <Field label="邮箱" icon="mail" type="email" placeholder="owner@chenxing.star" value={email} onChange={(event) => setEmail(event.target.value)} required />
                <PasswordField
                  label="密码"
                  icon="lock-keyhole"
                  placeholder={`${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个字符`}
                  value={password}
                  onChange={(event) => setPassword(limitPasswordInput(event.target.value))}
                  maxLength={PASSWORD_MAX_INPUT_LENGTH}
                  hint={`长度为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个 Unicode 字符。`}
                  required
                />
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
