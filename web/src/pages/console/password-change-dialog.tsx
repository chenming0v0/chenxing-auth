import { useEffect, useRef, type FormEvent } from 'react'
import { Button, HudPanel, Icon, PasswordField } from '../../components/ui'

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
  const cancelRef = useRef(onCancel)

  useEffect(() => { cancelRef.current = onCancel }, [onCancel])
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    document.getElementById('password-change-current')?.focus()
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault()
      cancelRef.current()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      previousFocus?.focus()
    }
  }, [])

  return (
    <div
      className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center overflow-y-auto bg-black/70 p-4"
      role="presentation"
      onMouseDown={(event) => { if (event.target === event.currentTarget) onCancel() }}
    >
      <HudPanel
        as="form"
        role="dialog"
        aria-modal="true"
        aria-labelledby="password-change-title"
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-lg"
        onSubmit={onSubmit}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Password Security</p>
            <h2 id="password-change-title" className="chenxing-h2 mt-2">修改密码</h2>
            <p className="chenxing-caption mt-2">修改成功后，所有现有会话都会被撤销，需要使用新密码重新登录。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel}>
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
    </div>
  )
}
