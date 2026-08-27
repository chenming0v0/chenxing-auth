import { useModalFocus } from '@chenxing/ui'
import { Button, Field, HudPanel, Icon, PasswordField } from '@chenxing/ui'
import type { FormEvent } from 'react'

type ProfileEditorDialogProps = {
  displayName: string
  username: string
  password: string
  busy: boolean
  usernameChangePending: boolean
  onDisplayName: (value: string) => void
  onUsername: (value: string) => void
  onPassword: (value: string) => void
  onCancel: () => void
  onSubmit: (event: FormEvent) => void
}

export function ProfileEditorDialog({
  displayName,
  username,
  password,
  busy,
  usernameChangePending,
  onDisplayName,
  onUsername,
  onPassword,
  onCancel,
  onSubmit,
}: ProfileEditorDialogProps) {
  function requestCancel() {
    if (!busy) onCancel()
  }
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: '#profile-display-name',
    escapeDisabled: busy,
  })

  return (
    <div
      className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center overflow-y-auto bg-black/70 p-4"
      role="presentation"
      onMouseDown={(event) => { if (event.target === event.currentTarget) requestCancel() }}
    >
      <HudPanel
        as="form"
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="profile-editor-title"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-2xl"
        onSubmit={onSubmit}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Account Profile</p>
            <h2 id="profile-editor-title" className="chenxing-h2 mt-2">修改账户资料</h2>
            <p className="chenxing-caption mt-2">显示名称会公开展示；用户名属于登录身份，修改时需要重新认证。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={requestCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>

        <div className="mt-6 grid gap-4 md:grid-cols-2">
          <Field id="profile-display-name" label="显示名称" value={displayName} maxLength={256} hint="最多 128 个 Unicode 字符。" onChange={(event) => onDisplayName(event.target.value)} />
          <Field label="用户名" value={username} maxLength={64} autoCapitalize="none" spellCheck={false} hint="3-64 位，可使用小写字母、数字、点、下划线和连字符。" onChange={(event) => onUsername(event.target.value)} />
        </div>

        {usernameChangePending ? (
          <div className="mt-5 space-y-4">
            <PasswordField label="当前密码" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} required hint="用户名变化属于敏感操作，需要重新确认当前密码。" />
          </div>
        ) : null}

        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button
            type="submit"
            icon="check"
            disabled={busy}
          >
            {busy ? '保存中…' : '保存账户资料'}
          </Button>
        </div>
      </HudPanel>
    </div>
  )
}
