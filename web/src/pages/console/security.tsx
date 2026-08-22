import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { useLocation, useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, type SecurityEnrollmentResult, type SecurityFactorSummary, type SecurityPasskeyStart, type SecurityRemovalResult, type SecurityTotpStart } from '../../api'
import { assertPublicKeyCredential, decodeCreationOptions, serializeAttestation, supportsWebAuthnCreate, type PasskeyChallenge } from '../../passkey'
import { useDrawerFocus } from '../../components/drawer'
import { Badge, Button, HudPanel, Icon, Notice, PasswordField } from '../../components/ui'
import { useModalFocus } from '../../components/modal'
import { ExternalIdentities } from './external-identities'
import type { MessageTone } from './profile-avatar'
import { SecuritySettings, type SecurityFactorState } from './security-settings'

type NoticeState = { text: string; tone: MessageTone }
type TotpState = { phase: 'idle' } | { phase: 'ready'; data: SecurityTotpStart }

type AccountTab = 'bindings' | 'security'

export function AccountManagement({ userEmail, profileSummary, profileAction, emailAction, passwordAction }: {
  userEmail: string
  profileSummary: string
  profileAction: ReactNode
  emailAction: ReactNode
  passwordAction: ReactNode
}) {
  const { clear } = useAuth()
  const navigate = useNavigate()
  const { search } = useLocation()
  const [factors, setFactors] = useState<SecurityFactorState>({ status: 'loading' })
  const factorRequestIdRef = useRef(0)
  const mountedRef = useRef(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<NoticeState | null>(null)
  const [totp, setTotp] = useState<TotpState>({ phase: 'idle' })
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [removing, setRemoving] = useState<'totp' | 'passkey' | null>(null)
  const [activeTab, setActiveTab] = useState<AccountTab>('bindings')

  async function loadFactors(): Promise<void> {
    const requestId = ++factorRequestIdRef.current
    setFactors({ status: 'loading' })
    try {
      const summary = await apiFetch<SecurityFactorSummary>('/api/v1/auth/security/factors')
      if (!mountedRef.current || requestId !== factorRequestIdRef.current) return
      setFactors({ status: 'ready', summary })
    } catch (error) {
      if (!mountedRef.current || requestId !== factorRequestIdRef.current) return
      setFactors({ status: 'failed' })
      setNotice({ text: error instanceof Error ? error.message : '登录安全状态加载失败。', tone: 'warning' })
    }
  }

  useEffect(() => {
    mountedRef.current = true
    void loadFactors()
    return () => {
      mountedRef.current = false
      factorRequestIdRef.current += 1
    }
  }, [])

  useEffect(() => {
    const result = new URLSearchParams(search).get('external')
    const error = new URLSearchParams(search).get('external_error')
    if (result === 'linked') show('外部账户已绑定。', 'success')
    else if (error) show(externalBindingErrorMessage(error))
    if (result || error) window.history.replaceState({}, '', '/console/profile')
  }, [search])

  function show(text: string, tone: MessageTone = 'warning') {
    setNotice({ text, tone })
  }

  async function startTotp(): Promise<void> {
    if (busy) return
    setBusy('totp-start')
    setNotice(null)
    try {
      const data = await apiFetch<SecurityTotpStart>('/api/v1/auth/security/totp/enrollment/start', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({}),
      })
      setTotp({ phase: 'ready', data })
      setCode('')
    } catch (error) {
      show(error instanceof Error ? error.message : '无法开始 TOTP 绑定。')
    } finally {
      setBusy(null)
    }
  }

  function cancelTotp(): void {
    if (totp.phase !== 'ready' || busy) {
      if (totp.phase === 'idle') return
      setTotp({ phase: 'idle' })
      setCode('')
      return
    }
    const enrollmentId = totp.data.enrollment_id
    setBusy('totp-cancel')
    void apiFetch<{ cancelled: true }>('/api/v1/auth/security/factor/enrollment/cancel', {
      method: 'POST',
      redirectOn401: false,
      body: JSON.stringify({ enrollment_id: enrollmentId, method: 'totp' }),
    }).then(() => {
      setTotp({ phase: 'idle' })
      setCode('')
    }).catch((error) => {
      show(error instanceof Error ? error.message : '取消 TOTP 绑定失败，请重试。')
    }).finally(() => {
      setBusy(null)
    })
  }
  async function confirmTotp(event: FormEvent): Promise<void> {
    event.preventDefault()
    if (busy || !/^\d{6}$/.test(code)) {
      if (!busy) show('请输入 6 位验证码。')
      return
    }
    if (totp.phase !== 'ready') return
    const { data } = totp
    setBusy('totp-confirm')
    setNotice(null)
    try {
      const result = await apiFetch<SecurityEnrollmentResult>('/api/v1/auth/security/totp/enrollment/confirm', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ enrollment_id: data.enrollment_id, code }),
      })
      setTotp({ phase: 'idle' })
      setCode('')
      show(result.enabled ? 'TOTP 已启用。下次登录将需要验证码。' : 'TOTP 尚未启用。', 'success')
      await loadFactors()
    } catch (error) {
      show(error instanceof Error ? error.message : 'TOTP 验证失败。')
    } finally {
      setBusy(null)
    }
  }

  async function startPasskey(): Promise<void> {
    if (busy) return
    if (!supportsWebAuthnCreate()) {
      show('当前浏览器不支持 Passkey，请使用支持 WebAuthn 的浏览器。')
      return
    }
    setBusy('passkey')
    setNotice(null)
    try {
      const start = await apiFetch<SecurityPasskeyStart>('/api/v1/auth/security/passkeys/registration/start', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({}),
      })
      const options = decodeCreationOptions(start.options as PasskeyChallenge)
      let credential: PublicKeyCredential
      try {
        credential = assertPublicKeyCredential(await navigator.credentials.create({ publicKey: options }))
      } catch (error) {
        if (error instanceof DOMException && (error.name === 'NotAllowedError' || error.name === 'AbortError')) {
          await apiFetch('/api/v1/auth/security/factor/enrollment/cancel', {
            method: 'POST',
            redirectOn401: false,
            body: JSON.stringify({ enrollment_id: start.enrollment_id, method: 'passkey' }),
          }).catch(() => undefined)
          show('Passkey 注册已取消，可以立即重试。')
          return
        }
        throw error
      }
      const result = await apiFetch<SecurityEnrollmentResult>('/api/v1/auth/security/passkeys/registration/finish', {
        method: 'POST',
        redirectOn401: false,
        body: JSON.stringify({ enrollment_id: start.enrollment_id, credential: serializeAttestation(credential) }),
      })
      show(result.enabled ? 'Passkey 已启用。下次登录可使用此设备验证。' : 'Passkey 尚未启用。', 'success')
      await loadFactors()
    } catch (error) {
      show(error instanceof Error ? error.message : 'Passkey 注册失败。')
    } finally {
      setBusy(null)
    }
  }

  async function removeFactor(): Promise<void> {
    if (!removing || busy) return
    if (!password) {
      show('请输入当前密码完成重新认证。')
      return
    }
    setBusy(`remove-${removing}`)
    setNotice(null)
    try {
      const result = await apiFetch<SecurityRemovalResult>(`/api/v1/auth/security/factors/${removing}`, {
        method: 'DELETE',
        redirectOn401: false,
        body: JSON.stringify({ password }),
      })
      setRemoving(null)
      setPassword('')
      clear()
      navigate('/login?returnTo=%2Fconsole%2Fprofile')
      void result
    } catch (error) {
      show(error instanceof Error ? error.message : '认证因子移除失败。')
    } finally {
      setBusy(null)
    }
  }

  const summary = factors.status === 'ready' ? factors.summary : null
  const protectedAccount = summary !== null && (summary.totp_enabled || summary.passkey_count > 0)
  const readyTotp = totp.phase === 'ready' ? totp : null

  return (
    <div className="min-w-0 space-y-4">
      {notice ? <Notice tone={notice.tone}>{notice.text}</Notice> : null}
      <HudPanel id="account-management" as="section" aria-labelledby="account-management-title" className="!p-4 sm:!p-6">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[var(--chenxing-border)] pb-5">
          <div className="flex min-w-0 items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[rgba(103,232,249,0.24)] bg-[var(--chenxing-cyan-soft)] text-[var(--chenxing-cyan)]">
              <Icon name="user-plus" size={20} />
            </span>
            <div>
              <h2 id="account-management-title" className="chenxing-h2">账户管理</h2>
              <p className="chenxing-caption mt-1">账户绑定、安全设置和身份验证集中在这里管理。</p>
            </div>
          </div>
          <Badge tone={factors.status === 'failed' ? 'warning' : protectedAccount ? 'success' : 'neutral'}>
            {factors.status === 'loading' ? '同步中' : factors.status === 'failed' ? '状态未知' : protectedAccount ? '安全增强已启用' : '基础保护'}
          </Badge>
        </div>

        <div className="mt-5 grid grid-cols-2 gap-1 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.5)] p-1" role="tablist" aria-label="账户管理">
          <AccountTabButton tab="bindings" activeTab={activeTab} icon="link" label="账户绑定" onSelect={setActiveTab} />
          <AccountTabButton tab="security" activeTab={activeTab} icon="shield-check" label="安全设置" onSelect={setActiveTab} />
        </div>

        <div className="mt-6">
          {activeTab === 'bindings' ? (
            <div id="account-bindings-panel" role="tabpanel" aria-labelledby="account-bindings-tab">
              <ExternalIdentities userEmail={userEmail} busy={busy} onBusy={setBusy} onNotice={setNotice} />
            </div>
          ) : (
            <div id="security-settings-panel" role="tabpanel" aria-labelledby="security-settings-tab">
              <SecuritySettings
                factors={factors}
                busy={busy}
                totpData={readyTotp?.data ?? null}
                code={code}
                onCode={setCode}
                onStartTotp={() => void startTotp()}
                onCancelTotp={cancelTotp}
                onConfirmTotp={(event) => void confirmTotp(event)}
                onStartPasskey={() => void startPasskey()}
                onRemove={setRemoving}
                profileSummary={profileSummary}
                profileAction={profileAction}
                userEmail={userEmail}
                emailAction={emailAction}
                passwordAction={passwordAction}
              />
            </div>
          )}
        </div>
      </HudPanel>

      {removing ? <RemovalDialog method={removing} password={password} busy={busy !== null} onPassword={setPassword} onCancel={() => { setRemoving(null); setPassword('') }} onConfirm={() => void removeFactor()} /> : null}
    </div>
  )
}

function AccountTabButton({ tab, activeTab, icon, label, onSelect }: {
  tab: AccountTab
  activeTab: AccountTab
  icon: string
  label: string
  onSelect: (tab: AccountTab) => void
}) {
  const selected = activeTab === tab
  const tabId = tab === 'bindings' ? 'account-bindings-tab' : 'security-settings-tab'
  const panelId = tab === 'bindings' ? 'account-bindings-panel' : 'security-settings-panel'
  return (
    <button
      id={tabId}
      type="button"
      role="tab"
      aria-selected={selected}
      aria-controls={panelId}
      tabIndex={selected ? 0 : -1}
      className={`flex min-h-11 items-center justify-center gap-2 rounded-[calc(var(--chenxing-radius-md)-2px)] px-3 text-sm font-semibold transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--chenxing-cyan)] ${selected ? 'bg-[var(--chenxing-muted)] text-[var(--chenxing-foreground)] shadow-[inset_0_0_0_1px_var(--chenxing-border-strong)]' : 'text-[var(--chenxing-muted-foreground)] hover:bg-[rgba(255,255,255,0.04)] hover:text-[var(--chenxing-foreground)]'}`}
      onClick={() => onSelect(tab)}
    >
      <Icon name={icon} size={16} className={selected ? 'text-[var(--chenxing-cyan)]' : ''} />
      {label}
    </button>
  )
}

function RemovalDialog({ method, password, busy, onPassword, onCancel, onConfirm }: { method: 'totp' | 'passkey'; password: string; busy: boolean; onPassword: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  const containerRef = useModalFocus<HTMLElement>(onCancel, {
    initialFocusSelector: '#remove-factor-password',
    escapeDisabled: busy,
  })

  return (
    <div className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center bg-black/70 p-4" role="presentation">
      <HudPanel ref={containerRef} as="section" role="dialog" aria-modal="true" aria-labelledby="remove-factor-title" tabIndex={-1} className="relative z-[var(--chenxing-z-dialog)] w-full max-w-md">
        <div className="flex items-start justify-between gap-4"><div><p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Re-authentication</p><h2 id="remove-factor-title" className="chenxing-h2 mt-2">移除{method === 'totp' ? ' TOTP' : '全部 Passkey'}</h2></div><button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onCancel} disabled={busy}><Icon name="x" size={17} /></button></div>
        <p className="chenxing-caption mt-4">这是敏感安全操作。移除后所有活跃会话都会失效，并需要重新登录。请输入当前密码确认身份。</p>
        <div className="mt-5"><PasswordField id="remove-factor-password" label="当前密码" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} /></div>
        <div className="mt-5 flex flex-wrap justify-end gap-3"><Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button><Button type="button" variant="danger" icon="trash-2" onClick={onConfirm} disabled={busy}>{busy ? '处理中…' : '确认移除'}</Button></div>
      </HudPanel>
    </div>
  )
}

function externalBindingErrorMessage(code: string): string {
  const messages: Record<string, string> = {
    oauth_binding_failed: '外部账户绑定未完成，请重试。',
    oauth_binding_state_invalid: '外部绑定流程已失效，请重新开始。',
    oauth_binding_epoch_conflict: '登录会话已变化，请重新开始绑定。',
    oauth_identity_already_linked: '该外部账户已经绑定到当前账号。',
    oauth_identity_owned_by_another_user: '该外部账户已绑定到其他辰星账号。',
    oauth_email_unverified: '外部身份源未确认邮箱已验证，无法绑定。',
    oauth_provider_not_found: '该外部身份源不可用或已停用。',
  }
  return messages[code] ?? '外部账户绑定未完成，请重试。'
}
