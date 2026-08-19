import { useEffect, useRef, type FormEvent } from 'react'
import { Button, Field, HudPanel, Icon, Notice, PasswordField } from '../../components/ui'

type EmailChangeDialogProps = {
  currentEmail: string
  newEmail: string
  password: string
  onNewEmail: (value: string) => void
  onPassword: (value: string) => void
  onCancel: () => void
  onSubmit: (event: FormEvent) => void
}

export function EmailChangeDialog({
  currentEmail,
  newEmail,
  password,
  onNewEmail,
  onPassword,
  onCancel,
  onSubmit,
}: EmailChangeDialogProps) {
  const cancelRef = useRef(onCancel)

  useEffect(() => { cancelRef.current = onCancel }, [onCancel])
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null
    document.getElementById('new-email-address')?.focus()
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
      <HudPanel as="form" role="dialog" aria-modal="true" aria-labelledby="email-change-title" className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-lg" onSubmit={onSubmit}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Email Security</p>
            <h2 id="email-change-title" className="chenxing-h2 mt-2">更改邮箱</h2>
            <p className="chenxing-caption mt-2">新邮箱验证通过后才会替换当前登录邮箱。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel}>
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="mt-6 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] px-4 py-3">
          <p className="chenxing-caption">当前邮箱</p>
          <p className="chenxing-body chenxing-mono mt-1 break-all text-sm font-semibold">{currentEmail}</p>
        </div>

        <div className="mt-5 space-y-4">
          <Field id="new-email-address" label="新邮箱地址" icon="mail" type="email" autoComplete="email" value={newEmail} maxLength={254} required onChange={(event) => onNewEmail(event.target.value)} />
          <PasswordField label="当前密码" autoComplete="current-password" value={password} required hint="邮箱变化属于敏感操作，需要重新确认当前密码。" onChange={(event) => onPassword(event.target.value)} />
          <Notice tone="warning">邮箱变更后端尚未实现，当前不会提交修改。</Notice>
        </div>

        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel}>取消</Button>
          <Button type="submit" icon="mail" aria-disabled="true">等待后端接入</Button>
        </div>
      </HudPanel>
    </div>
  )
}
