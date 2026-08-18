import { useEffect, useState, type FormEvent } from 'react'
import QRCode from 'qrcode'
import { useLocation, useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, type SecurityEnrollmentResult, type SecurityFactorSummary, type SecurityPasskeyStart, type SecurityRemovalResult, type SecurityTotpStart } from '../../api'
import { assertPublicKeyCredential, decodeCreationOptions, serializeAttestation, supportsWebAuthnCreate, type PasskeyChallenge } from '../../passkey'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, CopyValue, EmptyState, HudPanel, Icon, Notice, PageIntro, PasswordField } from '../../components/ui'
import { ExternalIdentities } from './external-identities'
import type { MessageTone } from './profile-avatar'

type NoticeState = { text: string; tone: MessageTone }
type TotpState = { phase: 'idle' } | { phase: 'ready'; data: SecurityTotpStart }

type VerificationMethod = {
  key: 'passkey' | 'totp'
  title: string
  description: string
  icon: string
  accentClass: string
}

const verificationMethods: VerificationMethod[] = [
  { key: 'passkey', title: 'Passkey', description: '使用设备生物识别或安全密钥登录，不需要输入验证码。', icon: 'key-round', accentClass: 'text-[var(--chenxing-gold)]' },
  { key: 'totp', title: '验证器应用', description: '使用验证器应用生成一次性验证码，作为密码登录后的第二步验证。', icon: 'shield-check', accentClass: 'text-[var(--chenxing-cyan)]' },
]

export function ConsoleSecurity() {
  const { clear } = useAuth()
  const navigate = useNavigate()
  const { search } = useLocation()
  const [summary, setSummary] = useState<SecurityFactorSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<NoticeState | null>(null)
  const [totp, setTotp] = useState<TotpState>({ phase: 'idle' })
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [removing, setRemoving] = useState<'totp' | 'passkey' | null>(null)

  async function loadFactors(): Promise<void> {
    setLoading(true)
    try {
      setSummary(await apiFetch<SecurityFactorSummary>('/api/v1/auth/security/factors'))
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : '登录安全状态加载失败。', tone: 'warning' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadFactors() }, [])

  useEffect(() => {
    const result = new URLSearchParams(search).get('external')
    const error = new URLSearchParams(search).get('external_error')
    if (result === 'linked') show('外部账户已绑定。', 'success')
    else if (error) show(externalBindingErrorMessage(error))
    if (result || error) window.history.replaceState({}, '', '/console/security')
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
        body: JSON.stringify({}),
      })
      const options = decodeCreationOptions(start.options as PasskeyChallenge)
      const credential = assertPublicKeyCredential(await navigator.credentials.create({ publicKey: options }))
      const result = await apiFetch<SecurityEnrollmentResult>('/api/v1/auth/security/passkeys/registration/finish', {
        method: 'POST',
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
        body: JSON.stringify({ password }),
      })
      setRemoving(null)
      setPassword('')
      clear()
      navigate('/login?returnTo=%2Fconsole%2Fsecurity')
      void result
    } catch (error) {
      show(error instanceof Error ? error.message : '认证因子移除失败。')
    } finally {
      setBusy(null)
    }
  }

  const totpEnabled = summary?.totp_enabled ?? false
  const passkeyCount = summary?.passkey_count ?? 0
  const readyTotp = totp.phase === 'ready' ? totp : null

  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Account · Login Security"
        title="登录安全"
        description="主动启用 TOTP 或 Passkey。启用后，后续密码登录会要求完成第二步验证。"
      />
      {notice ? <div className="mb-5"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}

      <HudPanel as="section" aria-labelledby="login-verification-title">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="mb-2 flex items-center gap-2"><Icon name="shield-check" className="text-[var(--chenxing-cyan)]" size={20} /><h2 id="login-verification-title" className="chenxing-h2">登录验证</h2></div>
            <p className="chenxing-caption max-w-2xl">为密码登录增加独立验证方式。每种方式可单独启用，按需保留多个 Passkey 凭据。</p>
          </div>
          <Badge tone={totpEnabled || passkeyCount > 0 ? 'success' : 'neutral'}>{loading ? '读取中' : totpEnabled || passkeyCount > 0 ? '已保护' : '仅密码'}</Badge>
        </div>

        <div className="mt-6 divide-y divide-[var(--chenxing-border)] border-y border-[var(--chenxing-border)]">
          {verificationMethods.map((method) => {
            const enabled = method.key === 'totp' ? totpEnabled : passkeyCount > 0
            const status = method.key === 'totp'
              ? enabled ? '已启用' : '未启用'
              : enabled ? `${passkeyCount} 个凭据` : '未启用'
            return (
              <div key={method.key} className="py-5 first:pt-4 last:pb-4">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="flex min-w-0 items-start gap-3">
                    <span className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] ${method.accentClass}`}><Icon name={method.icon} size={18} /></span>
                    <div>
                      <h3 className="chenxing-body text-sm font-semibold">{method.title}</h3>
                      <p className="chenxing-caption mt-1 max-w-2xl">{method.description}</p>
                    </div>
                  </div>
                  <Badge tone={enabled ? 'success' : 'neutral'}>{loading ? '读取中' : status}</Badge>
                </div>

                {method.key === 'totp' ? (
                  totpEnabled ? (
                    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 pl-12">
                      <p className="chenxing-caption">移除后当前会话会失效，需要重新登录。</p>
                      <Button variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => setRemoving('totp')}>移除验证器应用</Button>
                    </div>
                  ) : readyTotp ? (
                    <div className="mt-5 space-y-5 pl-12">
                      <TotpQr url={readyTotp.data.otpauth_url} />
                      <div><span className="chenxing-label">手动密钥</span><CopyValue value={readyTotp.data.secret_base32} ariaLabel="复制 TOTP 手动密钥" announceValue /></div>
                      <form className="space-y-4" onSubmit={(event) => void confirmTotp(event)}>
                        <label className="chenxing-label" htmlFor="security-totp-code">确认验证码</label>
                        <input id="security-totp-code" className="chenxing-field" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))} aria-describedby="security-totp-hint" />
                        <p id="security-totp-hint" className="chenxing-caption">在验证器中输入当前 6 位验证码以完成绑定。</p>
                        <div className="flex flex-wrap gap-3"><Button type="submit" icon="check" disabled={busy !== null}>{busy === 'totp-confirm' ? '确认中…' : '确认并启用'}</Button><Button type="button" variant="ghost" onClick={() => setTotp({ phase: 'idle' })} disabled={busy !== null}>取消</Button></div>
                      </form>
                    </div>
                  ) : <div className="mt-4 pl-12"><Button icon="plus" disabled={busy !== null || loading} onClick={() => void startTotp()}>{busy === 'totp-start' ? '准备中…' : '启用 TOTP'}</Button></div>
                ) : (
                  <div className="mt-4 flex flex-wrap items-center gap-3 pl-12">
                    <p className="chenxing-caption mr-auto">{passkeyCount > 0 ? '新增设备不会移除已有凭据。' : '注册后，下次登录可选择使用 Passkey。'}</p>
                    <Button icon="key-round" disabled={busy !== null || loading} onClick={() => void startPasskey()}>{busy === 'passkey' ? '等待设备确认…' : '注册 Passkey'}</Button>
                    {passkeyCount > 0 ? <Button variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => setRemoving('passkey')}>移除全部 Passkey</Button> : null}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </HudPanel>

      <ExternalIdentities busy={busy} onBusy={setBusy} onNotice={setNotice} />

      {!loading && !totpEnabled && passkeyCount === 0 ? <HudPanel className="mt-5"><EmptyState icon="shield" title="当前使用密码登录" description="没有启用验证方式时，密码验证成功会直接建立普通会话。" /></HudPanel> : null}

      {removing ? <RemovalDialog method={removing} password={password} busy={busy !== null} onPassword={setPassword} onCancel={() => { setRemoving(null); setPassword('') }} onConfirm={() => void removeFactor()} /> : null}
    </ConsoleLayout>
  )
}

function RemovalDialog({ method, password, busy, onPassword, onCancel, onConfirm }: { method: 'totp' | 'passkey'; password: string; busy: boolean; onPassword: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  return (
    <div className="fixed inset-0 z-[var(--chenxing-z-modal)] flex items-center justify-center bg-black/70 p-4" role="presentation">
      <HudPanel as="section" role="dialog" aria-modal="true" aria-labelledby="remove-factor-title" className="w-full max-w-md">
        <div className="flex items-start justify-between gap-4"><div><p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Re-authentication</p><h2 id="remove-factor-title" className="chenxing-h2 mt-2">移除{method === 'totp' ? ' TOTP' : '全部 Passkey'}</h2></div><button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onCancel}><Icon name="x" size={17} /></button></div>
        <p className="chenxing-caption mt-4">这是敏感安全操作。移除后所有活跃会话都会失效，并需要重新登录。请输入当前密码确认身份。</p>
        <div className="mt-5"><PasswordField label="当前密码" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} /></div>
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

function TotpQr({ url }: { url: string }) {
  const [data, setData] = useState<string | null>(null)
  useEffect(() => { let cancelled = false; void QRCode.toDataURL(url, { errorCorrectionLevel: 'M', margin: 1, width: 220, color: { dark: '#06101f', light: '#f8fbff' } }).then((value) => { if (!cancelled) setData(value) }).catch(() => { if (!cancelled) setData(null) }); return () => { cancelled = true } }, [url])
  return <div><span className="chenxing-label">扫码绑定</span><div className="cx-totp-qr mt-2">{data ? <img src={data} alt="TOTP 绑定二维码" className="cx-totp-qr-image" /> : <span className="chenxing-caption">二维码生成失败，请使用手动密钥。</span>}</div></div>
}
