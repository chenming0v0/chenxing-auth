import { useState, type FormEvent } from 'react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { apiFetch, type LoginResponse, type PendingLoginResponse, type TotpSetupResponse } from '../api'
import { AuthPanel, AuthShell } from '../components/shells'
import { Button, CopyValue, Field, Notice } from '../components/ui'

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
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [pending, setPending] = useState<PendingLoginResponse | null>(null)
  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null)
  const isLogin = mode === 'login'

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
      if ('login_ticket' in response) {
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

  return <AuthShell action={isLogin ? '创建通行证' : '返回登录'} actionTo={isLogin ? '/register' : '/login'}>
    <AuthPanel>
      <header><span className="eyebrow">{isLogin ? 'SIGN IN · 02' : 'CREATE ID · 03'}</span><h1 className="chenxing-h1">{isLogin ? '欢迎回到辰星' : '创建你的通行证'}</h1><p>{isLogin ? '使用已注册的身份进入辰星认证中枢。' : '从一个安全、清晰的身份开始连接你的应用。'}</p></header>
      {query.get('registered') && <div className="auth-feedback"><Notice tone="success">注册成功，请使用新账号登录。</Notice></div>}
      {message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}
      {pending ? <PendingFactorStep pending={pending} setup={totpSetup} busy={busy} onSetup={setTotpSetup} onComplete={completeLogin} onBusy={setBusy} onMessage={setMessage} /> : <form className="auth-form" onSubmit={submit}>
        {!isLogin && <Field label="用户名" placeholder="chenxing_user" autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} required />}
        <Field label={isLogin ? '邮箱或用户名' : '邮箱地址'} type={isLogin ? 'text' : 'email'} placeholder={isLogin ? 'name@example.com' : 'name@example.com'} autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        {!isLogin && <Field label="显示名称" placeholder="可选" autoComplete="nickname" value={displayName} onChange={(event) => setDisplayName(event.target.value)} />}
        <Field label="密码" type="password" placeholder="至少 10 位字符" autoComplete={isLogin ? 'current-password' : 'new-password'} value={password} onChange={(event) => setPassword(event.target.value)} hint={!isLogin ? '请使用高强度密码保护账号。' : undefined} />
        {isLogin && <div className="form-options"><label className="check-row"><input type="checkbox" />保持登录</label><span className="field-hint">需要帮助请联系管理员</span></div>}
        <Button type="submit" icon={isLogin ? 'log-in' : 'rocket'} disabled={busy}>{busy ? '处理中…' : isLogin ? '进入控制台' : '创建通行证'}</Button>
      </form>}
      {!pending && <footer className="auth-footer">{isLogin ? '还没有通行证？' : '已经拥有通行证？'}<Link to={isLogin ? '/register' : '/login'}>{isLogin ? '立即创建' : '前往登录'}</Link></footer>}
    </AuthPanel>
  </AuthShell>
}

function PendingFactorStep({
  pending,
  setup,
  busy,
  onSetup,
  onComplete,
  onBusy,
  onMessage,
}: {
  pending: PendingLoginResponse
  setup: TotpSetupResponse | null
  busy: boolean
  onSetup: (value: TotpSetupResponse) => void
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => void
  onMessage: (value: string) => void
}) {
  const hasTotp = pending.methods.includes('totp')
  const hasPasskey = pending.methods.includes('passkey')
  if (hasPasskey && !hasTotp) {
    return <PasskeyStep pending={pending} busy={busy} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
  }
  if (hasTotp) {
    return <TotpStep pending={pending} setup={setup} busy={busy} onSetup={onSetup} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
  }
  return <Notice tone="warning">当前账号没有可用的认证因子，请重新登录。</Notice>
}

function TotpStep({
  pending,
  setup,
  busy,
  onSetup,
  onComplete,
  onBusy,
  onMessage,
}: {
  pending: PendingLoginResponse
  setup: TotpSetupResponse | null
  busy: boolean
  onSetup: (value: TotpSetupResponse) => void
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => void
  onMessage: (value: string) => void
}) {
  const [code, setCode] = useState('')
  const setupRequired = pending.status === 'factor_setup_required'

  async function startSetup() {
    onMessage('')
    onBusy(true)
    try {
      onSetup(await apiFetch<TotpSetupResponse>('/api/v1/auth/totp/setup', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ login_ticket: pending.login_ticket }),
      }))
    } catch (error) {
      onMessage(error instanceof Error ? error.message : '无法开始验证器绑定。')
    } finally {
      onBusy(false)
    }
  }

  async function submitCode(event: FormEvent) {
    event.preventDefault()
    if (!/^\d{6}$/.test(code)) {
      onMessage('请输入 6 位验证码。')
      return
    }
    onMessage('')
    onBusy(true)
    try {
      await apiFetch<LoginResponse>(setupRequired ? '/api/v1/auth/totp/setup/confirm' : '/api/v1/auth/totp/login', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ login_ticket: pending.login_ticket, code }),
      })
      await onComplete()
    } catch (error) {
      onMessage(error instanceof Error ? error.message : '验证码校验失败。')
    } finally {
      onBusy(false)
    }
  }

  return <div className="auth-form">
    <Notice tone="info">{setupRequired ? '首次登录需要绑定验证器。' : '请输入验证器中的 6 位验证码。'}</Notice>
    {setupRequired && !setup && <Button type="button" icon="shield-check" onClick={startSetup} disabled={busy}>开始绑定验证器</Button>}
    {setup && <div className="content-grid"><div><span className="chenxing-label">验证器密钥</span><CopyValue value={setup.secret_base32} /></div><div><span className="chenxing-label">手动配置地址</span><CopyValue value={setup.otpauth_url} /></div></div>}
    {(!setupRequired || setup) && <form className="auth-form" onSubmit={submitCode}><Field label="一次性验证码" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))} /><Button type="submit" icon="check" disabled={busy}>{busy ? '验证中…' : '完成验证'}</Button></form>}
  </div>
}

type PasskeyAuthenticationStartResponse = {
  publicKey?: Record<string, unknown>
}

function PasskeyStep({
  pending,
  busy,
  onComplete,
  onBusy,
  onMessage,
}: {
  pending: PendingLoginResponse
  busy: boolean
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => void
  onMessage: (value: string) => void
}) {
  async function authenticate() {
    onMessage('')
    if (!supportsWebAuthn()) {
      onMessage('当前浏览器不支持 Passkey，请使用支持 WebAuthn 的浏览器。')
      return
    }
    onBusy(true)
    try {
      const options = await apiFetch<PasskeyAuthenticationStartResponse>('/api/v1/auth/passkeys/authentication/start', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ login_ticket: pending.login_ticket }),
      })
      const publicKey = decodeRequestOptions(options)
      const credential = await navigator.credentials.get({ publicKey })
      if (!credential || credential.type !== 'public-key') {
        throw new Error('Passkey assertion is unavailable')
      }
      await apiFetch<LoginResponse>('/api/v1/auth/passkeys/authentication/finish', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({
          login_ticket: pending.login_ticket,
          credential: serializeAssertion(credential as PublicKeyCredential),
        }),
      })
      await onComplete()
    } catch (error) {
      onMessage(passkeyErrorMessage(error))
    } finally {
      onBusy(false)
    }
  }

  return <div className="auth-form">
    <Notice tone="info">请使用已绑定的 Passkey 完成登录。</Notice>
    <Button type="button" icon="key-round" onClick={() => void authenticate()} disabled={busy}>{busy ? '验证中…' : '使用 Passkey 登录'}</Button>
  </div>
}

function supportsWebAuthn(): boolean {
  return typeof window !== 'undefined'
    && 'PublicKeyCredential' in window
    && typeof navigator.credentials?.get === 'function'
}

function decodeRequestOptions(options: PasskeyAuthenticationStartResponse): PublicKeyCredentialRequestOptions {
  if (!options.publicKey) throw new Error('Passkey challenge is invalid')
  const raw = options.publicKey
  const challenge = decodeBase64Url(raw.challenge)
  const allowCredentials = Array.isArray(raw.allowCredentials)
    ? raw.allowCredentials.map((value) => {
      if (!value || typeof value !== 'object') throw new Error('Passkey credential options are invalid')
      const descriptor = value as Record<string, unknown>
      return {
        type: 'public-key' as const,
        id: decodeBase64Url(descriptor.id),
      }
    })
    : undefined
  const userVerification = raw.userVerification
  return {
    challenge,
    ...(typeof raw.timeout === 'number' ? { timeout: raw.timeout } : {}),
    ...(typeof raw.rpId === 'string' ? { rpId: raw.rpId } : {}),
    ...(allowCredentials ? { allowCredentials } : {}),
    ...(['required', 'preferred', 'discouraged'].includes(String(userVerification))
      ? { userVerification: userVerification as UserVerificationRequirement }
      : {}),
  }
}

function decodeBase64Url(value: unknown): ArrayBuffer {
  if (typeof value !== 'string') throw new Error('Passkey challenge is invalid')
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  if (normalized.length % 4 === 1) throw new Error('Passkey challenge is invalid')
  try {
    const binary = atob(normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '='))
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
    return bytes.buffer
  } catch {
    throw new Error('Passkey challenge is invalid')
  }
}

function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function serializeAssertion(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
    },
    type: credential.type,
  }
}

function passkeyErrorMessage(error: unknown): string {
  if (typeof DOMException !== 'undefined' && error instanceof DOMException && (error.name === 'AbortError' || error.name === 'NotAllowedError')) {
    return 'Passkey 验证已取消，请重试。'
  }
  if (error instanceof Error && error.message === 'Passkey challenge is invalid') {
    return '服务返回的 Passkey challenge 无效，请重新登录。'
  }
  return error instanceof Error ? error.message : 'Passkey 验证失败，请重试。'
}

export function BootstrapPage() {
  const navigate = useNavigate()
  const [done, setDone] = useState(false)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setMessage('')
    setBusy(true)
    try {
      await apiFetch('/api/v1/admin/bootstrap', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ username: form.get('username'), email: form.get('email'), password: form.get('password') }),
      })
      setDone(true)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '初始化未完成，请稍后重试。')
    } finally {
      setBusy(false)
    }
  }
  return <AuthShell action="返回登录" actionTo="/login"><AuthPanel>
    <header><span className="eyebrow">SYSTEM BOOTSTRAP · 04</span><h1 className="chenxing-h1">初始化 Owner</h1><p>这是部署后的首次初始化入口。完成后，管理接口将进入受保护状态。</p></header>
    {message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}
    {done ? <><Notice tone="success">Owner 初始化成功，请使用新账号登录。</Notice><Button type="button" icon="log-in" onClick={() => navigate('/login')}>前往登录</Button></> : <form className="auth-form" onSubmit={submit}><Field label="用户名" name="username" autoComplete="username" required /><Field label="Owner 邮箱" name="email" type="email" autoComplete="email" required /><Field label="初始密码" name="password" type="password" autoComplete="new-password" hint="至少 10 位字符。" required /><Button type="submit" icon="shield-check" disabled={busy}>{busy ? '初始化中…' : '确认初始化'}</Button></form>}
    <footer className="auth-footer"><Link to="/login">返回统一登录</Link></footer>
  </AuthPanel></AuthShell>
}
