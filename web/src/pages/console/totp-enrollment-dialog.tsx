import { useEffect, useRef, useState, type FormEvent } from 'react'
import QRCode from 'qrcode'
import type { SecurityTotpStart } from '../../api'
import { Button, CopyValue, HudPanel, Icon } from '../../components/ui'

type TotpEnrollmentDialogProps = {
  data: SecurityTotpStart
  code: string
  busy: boolean
  confirming: boolean
  onCode: (value: string) => void
  onCancel: () => void
  onConfirm: (event: FormEvent) => void
}

export function TotpEnrollmentDialog({ data, code, busy, confirming, onCode, onCancel, onConfirm }: TotpEnrollmentDialogProps) {
  const cancelRef = useRef(onCancel)

  useEffect(() => { cancelRef.current = onCancel }, [onCancel])
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    document.getElementById('security-totp-code')?.focus()
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || busy) return
      event.preventDefault()
      cancelRef.current()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      previousFocus?.focus()
    }
  }, [busy])

  return (
    <div
      className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center overflow-y-auto bg-black/70 p-4"
      role="presentation"
      onMouseDown={(event) => { if (!busy && event.target === event.currentTarget) onCancel() }}
    >
      <HudPanel
        as="section"
        role="dialog"
        aria-modal="true"
        aria-labelledby="totp-enrollment-title"
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-3xl"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Authenticator Setup</p>
            <h2 id="totp-enrollment-title" className="chenxing-h2 mt-2">绑定验证器应用</h2>
            <p className="chenxing-caption mt-2">使用验证器扫描二维码，再输入当前显示的 6 位动态验证码完成绑定。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="mt-6 grid gap-6 md:grid-cols-[220px_minmax(0,1fr)] md:items-start">
          <TotpQr url={data.otpauth_url} />
          <div className="space-y-5">
            <div>
              <span className="chenxing-label">无法扫码？使用手动密钥</span>
              <CopyValue value={data.secret_base32} ariaLabel="复制 TOTP 手动密钥" announceValue />
            </div>
            <form className="space-y-4" onSubmit={onConfirm}>
              <div>
                <label className="chenxing-label" htmlFor="security-totp-code">确认验证码</label>
                <input
                  id="security-totp-code"
                  className="chenxing-field"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  value={code}
                  onChange={(event) => onCode(event.target.value.replace(/\D/g, ''))}
                  aria-describedby="security-totp-hint"
                />
                <p id="security-totp-hint" className="chenxing-caption mt-2">输入验证器当前显示的 6 位验证码，确认二维码和当前账户绑定正确。</p>
              </div>
              <div className="flex flex-wrap justify-end gap-3">
                <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
                <Button type="submit" icon="check" disabled={busy}>{confirming ? '确认中…' : '确认并启用'}</Button>
              </div>
            </form>
          </div>
        </div>
      </HudPanel>
    </div>
  )
}

function TotpQr({ url }: { url: string }) {
  const [data, setData] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void QRCode.toDataURL(url, {
      errorCorrectionLevel: 'M',
      margin: 1,
      width: 220,
      color: { dark: '#06101f', light: '#f8fbff' },
    }).then((value) => {
      if (!cancelled) setData(value)
    }).catch(() => {
      if (!cancelled) setData(null)
    })
    return () => { cancelled = true }
  }, [url])

  return (
    <div>
      <span className="chenxing-label">扫码绑定</span>
      <div className="cx-totp-qr mt-2">
        {data ? <img src={data} alt="TOTP 绑定二维码" className="cx-totp-qr-image" /> : <span className="chenxing-caption">二维码生成失败，请使用手动密钥。</span>}
      </div>
    </div>
  )
}
