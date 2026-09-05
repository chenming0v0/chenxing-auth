import { useModalFocus, ModalOverlay } from '@chenxing/ui'
import { Button, Field, HudPanel, Icon, Notice, PasswordField } from '@chenxing/ui'
import type { FormEvent } from 'react'

type EmailChangeDialogProps = {
  currentEmail: string
  newEmail: string
  password: string
  code: string
  stage: 'details' | 'verify'
  busy: boolean
  onNewEmail: (value: string) => void
  onPassword: (value: string) => void
  onCode: (value: string) => void
  onCancel: () => void
  onSubmit: (event: FormEvent) => void
}

export function EmailChangeDialog({
  currentEmail,
  newEmail,
  password,
  code,
  stage,
  busy,
  onNewEmail,
  onPassword,
  onCode,
  onCancel,
  onSubmit,
}: EmailChangeDialogProps) {
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: stage === 'details' ? '#new-email-address' : '#email-change-code',
    focusKey: stage,
    escapeDisabled: busy,
  })

  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel ref={containerRef} as="form" role="dialog" aria-modal="true" aria-labelledby="email-change-title" tabIndex={-1} className="w-full max-w-lg" onSubmit={onSubmit}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Email Security</p>
            <h2 id="email-change-title" className="chenxing-h2 mt-2">更改邮箱</h2>
            <p className="chenxing-caption mt-2">新邮箱验证通过后才会替换当前登录邮箱。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="mt-6 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] px-4 py-3">
          <p className="chenxing-caption">当前邮箱</p>
          <p className="chenxing-body chenxing-mono mt-1 break-all text-sm font-semibold">{currentEmail}</p>
        </div>

        {stage === 'details' ? (
          <div className="mt-5 space-y-4">
            <Field id="new-email-address" label="新邮箱地址" icon="mail" type="email" autoComplete="email" value={newEmail} maxLength={254} required onChange={(event) => onNewEmail(event.target.value)} />
            <PasswordField label="当前密码" autoComplete="current-password" value={password} required hint="邮箱变化属于敏感操作，需要重新确认当前密码。" onChange={(event) => onPassword(event.target.value)} />
            <Notice tone="info">验证码将发送到新邮箱，10 分钟内有效。</Notice>
          </div>
        ) : (
          <div className="mt-5 space-y-4">
            <Field id="email-change-code" label="邮箱验证码" icon="shield-check" inputMode="numeric" autoComplete="one-time-code" value={code} maxLength={6} pattern="[0-9]{6}" required onChange={(event) => onCode(event.target.value.replace(/[^0-9]/g, '').slice(0, 6))} />
            <Notice tone="info">验证码已排队发送到 {newEmail}。邮件投递采用至少一次语义，极少数故障恢复时可能重复收到邮件；请以最新验证码为准。确认后所有登录会话都会退出。</Notice>
          </div>
        )}

        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button type="submit" icon={stage === 'details' ? 'mail' : 'shield-check'} disabled={busy}>
            {busy ? (stage === 'details' ? '发送中…' : '确认中…') : stage === 'details' ? '发送验证码' : '确认变更'}
          </Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}
