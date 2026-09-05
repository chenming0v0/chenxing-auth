import { useModalFocus, ModalOverlay } from '@chenxing/ui'
import { Button, HudPanel, Icon, PasswordField } from '@chenxing/ui'
import type { FormEvent } from 'react'

type PasswordChangeDialogProps = {
  currentPassword: string
  newPassword: string
  confirmPassword: string
  busy: boolean
  maxInputLength: number
  passwordHint: string
  confirmError: boolean
  confirmHint: string
  onCurrentPassword: (value: string) => void
  onNewPassword: (value: string) => void
  onConfirmPassword: (value: string) => void
  onCancel: () => void
  onSubmit: (event: FormEvent) => void
}

export function PasswordChangeDialog({
  currentPassword,
  newPassword,
  confirmPassword,
  busy,
  maxInputLength,
  passwordHint,
  confirmError,
  confirmHint,
  onCurrentPassword,
  onNewPassword,
  onConfirmPassword,
  onCancel,
  onSubmit,
}: PasswordChangeDialogProps) {
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: '#password-change-current',
    escapeDisabled: busy,
  })

  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel
        as="form"
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-change-title"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-lg"
        onSubmit={onSubmit}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Password Security</p>
            <h2 id="password-change-title" className="chenxing-h2 mt-2">修改密码</h2>
            <p className="chenxing-caption mt-2">修改成功后，所有现有会话都会被撤销，需要使用新密码重新登录。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="mt-6 space-y-4">
          <PasswordField id="password-change-current" label="当前密码" autoComplete="current-password" value={currentPassword} onChange={(event) => onCurrentPassword(event.target.value)} required />
          <PasswordField label="新密码" autoComplete="new-password" value={newPassword} onChange={(event) => onNewPassword(event.target.value)} maxLength={maxInputLength} required hint={passwordHint} />
          <PasswordField label="确认新密码" autoComplete="new-password" value={confirmPassword} onChange={(event) => onConfirmPassword(event.target.value)} maxLength={maxInputLength} required error={confirmError} hint={confirmHint} />
        </div>

        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button type="submit" icon="key-round" disabled={busy}>{busy ? '修改中…' : '确认修改'}</Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}
