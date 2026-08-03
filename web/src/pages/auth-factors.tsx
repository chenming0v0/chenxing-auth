import { useEffect, useState, type FormEvent } from 'react'
import QRCode from 'qrcode'
import { apiFetch, type LoginResponse, type PendingLoginResponse, type TotpSetupResponse } from '../api'
import { Button, CopyValue, Field, Notice } from '../components/ui'

export function PendingFactorStep({
  pending, setup, busy, onSetup, onComplete, onBusy, onMessage,
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
  if (hasPasskey && !hasTotp) return <PasskeyStep pending={pending} busy={busy} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
  if (hasTotp) return <TotpStep pending={pending} setup={setup} busy={busy} onSetup={onSetup} onComplete={onComplete} onBusy={onBusy} onMessage={onMessage} />
  return <Notice tone="warning">当前账号没有可用的认证因子，请重新登录。</Notice>
}

function TotpStep({
  pending, setup, busy, onSetup, onComplete, onBusy, onMessage,
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
        method: 'POST', redirectOn401: false, body: JSON.stringify({ login_ticket: pending.login_ticket }),
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
        method: 'POST', redirectOn401: false, body: JSON.stringify({ login_ticket: pending.login_ticket, code }),
      })
      await onComplete()
    } catch (error) {
      onMessage(error instanceof Error ? error.message : '验证码校验失败。')
    } finally {
      onBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Notice tone="info">{setupRequired ? '首次登录需要绑定验证器。' : '请输入验证器中的 6 位验证码。'}</Notice>
      {setupRequired && !setup ? <Button type="button" icon="shield-check" onClick={startSetup} disabled={busy} className="w-full">开始绑定验证器</Button> : null}
      {setup ? (
        <div className="space-y-3">
          <TotpSetupQr otpauthUrl={setup.otpauth_url} />
          <div>
            <span className="chenxing-label">验证器密钥</span>
            <CopyValue value={setup.secret_base32} />
            <small className="chenxing-caption mt-1.5 block">无法扫码时，可在验证器中手动输入该密钥。</small>
          </div>
        </div>
      ) : null}
      {(!setupRequired || setup) ? (
        <form className="space-y-4" onSubmit={submitCode}>
          <Field label="一次性验证码" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="one-time-code" value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, ''))} />
          <Button type="submit" icon="check" disabled={busy} className="w-full">{busy ? '验证中…' : '完成验证'}</Button>
        </form>
      ) : null}
    </div>
  )
}

function TotpSetupQr({ otpauthUrl }: { otpauthUrl: string }) {
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    setQrDataUrl(null)
    setFailed(false)

    void QRCode.toDataURL(otpauthUrl, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 220,
      color: {
        dark: '#06101f',
        light: '#f8fbff',
      },
    })
      .then((value) => {
        if (!cancelled) setQrDataUrl(value)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })

    return () => {
      cancelled = true
    }
  }, [otpauthUrl])

  return (
    <div className="space-y-3">
      <span className="chenxing-label">扫码绑定</span>
      <div className="cx-totp-qr">
        {qrDataUrl ? (
          <img src={qrDataUrl} alt="TOTP 绑定二维码" className="cx-totp-qr-image" />
        ) : (
          <div className="cx-totp-qr-placeholder">
            {failed ? '二维码生成失败，请使用下方密钥手动添加。' : '正在生成二维码…'}
          </div>
        )}
      </div>
      <small className="chenxing-caption block text-center">使用 Google Authenticator、Microsoft Authenticator 或其他 TOTP 应用扫码。</small>
    </div>
  )
}

type PasskeyAuthenticationStartResponse = { publicKey?: Record<string, unknown> }

function PasskeyStep({
  pending, busy, onComplete, onBusy, onMessage,
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
        method: 'POST', redirectOn401: false, body: JSON.stringify({ login_ticket: pending.login_ticket }),
      })
      const publicKey = decodeRequestOptions(options)
      const credential = await navigator.credentials.get({ publicKey })
      if (!credential || credential.type !== 'public-key') throw new Error('Passkey assertion is unavailable')
      await apiFetch<LoginResponse>('/api/v1/auth/passkeys/authentication/finish', {
        method: 'POST', redirectOn401: false,
        body: JSON.stringify({ login_ticket: pending.login_ticket, credential: serializeAssertion(credential as PublicKeyCredential) }),
      })
      await onComplete()
    } catch (error) {
      onMessage(passkeyErrorMessage(error))
    } finally {
      onBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Notice tone="info">请使用已绑定的 Passkey 完成登录。</Notice>
      <Button type="button" icon="key-round" onClick={() => void authenticate()} disabled={busy} className="w-full">{busy ? '验证中…' : '使用 Passkey 登录'}</Button>
    </div>
  )
}

function supportsWebAuthn(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window && typeof navigator.credentials?.get === 'function'
}

function decodeRequestOptions(options: PasskeyAuthenticationStartResponse): PublicKeyCredentialRequestOptions {
  if (!options.publicKey) throw new Error('Passkey challenge is invalid')
  const raw = options.publicKey
  const challenge = decodeBase64Url(raw.challenge)
  const allowCredentials = Array.isArray(raw.allowCredentials)
    ? raw.allowCredentials.map((value) => {
      if (!value || typeof value !== 'object') throw new Error('Passkey credential options are invalid')
      const descriptor = value as Record<string, unknown>
      return { type: 'public-key' as const, id: decodeBase64Url(descriptor.id) }
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
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer
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
