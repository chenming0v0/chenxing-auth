import { useEffect, useState, type FormEvent } from 'react'
import QRCode from 'qrcode'
import { apiFetch, ApiError, type LoginResponse, type PendingLoginResponse, type TotpSetupResponse } from '../../api'
import { Button, CopyValue, Field, Notice } from '../../components/ui'

/**
 * login_ticket 是 MFA 步骤的会话凭证，失效（过期、被消费或服务端撤销）后
 * 后端统一返回 invalid_login_ticket。此时继续输入验证码只会反复失败，
 * 必须把控制权交还上层展示「重新登录」恢复动作，不能把用户卡在步骤里。
 */
function isInvalidLoginTicket(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'invalid_login_ticket'
}

export function TotpStep({
  pending, setup, busy, onSetup, onComplete, onBusy, onMessage, onTicketInvalid,
}: {
  pending: PendingLoginResponse
  setup: TotpSetupResponse | null
  busy: boolean
  onSetup: (value: TotpSetupResponse) => void
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => boolean | void
  onMessage: (value: string) => void
  onTicketInvalid: () => void
}) {
  const [code, setCode] = useState('')
  const setupRequired = pending.status === 'factor_setup_required'

  async function startSetup() {
    if (onBusy(true) === false) return
    onMessage('')
    try {
      onSetup(await apiFetch<TotpSetupResponse>('/api/v1/auth/totp/setup', {
        method: 'POST', redirectOn401: false, body: JSON.stringify({}),
      }))
    } catch (error) {
      if (isInvalidLoginTicket(error)) {
        onTicketInvalid()
        return
      }
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
    if (onBusy(true) === false) return
    onMessage('')
    try {
      await apiFetch<LoginResponse>(setupRequired ? '/api/v1/auth/totp/setup/confirm' : '/api/v1/auth/totp/login', {
        method: 'POST', redirectOn401: false, body: JSON.stringify({ code }),
      })
      await onComplete()
    } catch (error) {
      if (isInvalidLoginTicket(error)) {
        onTicketInvalid()
        return
      }
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
