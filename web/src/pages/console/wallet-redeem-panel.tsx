import { useState, type FormEvent } from 'react'
import { apiFetch, type WalletRedeemResult } from '../../api'
import { Button, Field, HudPanel, Icon, Notice } from '@chenxing/ui'

export function WalletRedeemPanel({ onRedeemed }: { onRedeemed: (result: WalletRedeemResult) => void }) {
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [success, setSuccess] = useState('')

  async function redeem(event: FormEvent) {
    event.preventDefault()
    const value = code.trim()
    if (!value) { setMessage('请输入兑换码。'); return }
    setBusy(true)
    setMessage('')
    setSuccess('')
    try {
      const result = await apiFetch<WalletRedeemResult>('/api/v1/auth/wallet/redeem', {
        method: 'POST',
        body: JSON.stringify({ code: value }),
      })
      setCode('')
      setSuccess(`兑换成功，已到账 ${result.points.toLocaleString('zh-CN')} 辰星点。`)
      onRedeemed(result)
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '兑换失败，请稍后重试。')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel as="section" aria-labelledby="wallet-redeem-title" className="flex flex-col">
      <div className="flex items-start gap-3.5">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-cyan)]">
          <Icon name="ticket" size={18} />
        </span>
        <div className="min-w-0">
          <h2 id="wallet-redeem-title" className="chenxing-h2">兑换辰星点</h2>
          <p className="chenxing-caption mt-1">输入管理员发放的兑换码，余额会立即增加。</p>
        </div>
      </div>
      {/* Field 的 className 落在内层 input 上，弹性伸缩必须交给这里的包装层，
          否则表单行会缩成内容宽、按钮悬在卡片中部留出大片空白。 */}
      <form className="mt-5 flex flex-col gap-4 sm:flex-row sm:items-end" onSubmit={redeem}>
        <div className="min-w-0 flex-1">
          <Field
            label="兑换码"
            icon="ticket"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            placeholder="输入兑换码"
            autoComplete="one-time-code"
            disabled={busy}
          />
        </div>
        <Button type="submit" icon="zap" className="shrink-0" disabled={busy}>{busy ? '兑换中…' : '立即兑换'}</Button>
      </form>
      {message ? <div className="mt-4"><Notice tone="warning">{message}</Notice></div> : null}
      {success ? <div className="mt-4"><Notice tone="success">{success}</Notice></div> : null}
    </HudPanel>
  )
}
