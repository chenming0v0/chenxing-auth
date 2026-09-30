import { Button, HudPanel, Icon, ModalOverlay, Notice, useModalFocus } from '@chenxing/ui'

type RevokeAppDialogProps = {
  name: string
  busy: boolean
  onCancel: () => void
  onConfirm: () => void
}

export function RevokeAppDialog({ name, busy, onCancel, onConfirm }: RevokeAppDialogProps) {
  function requestCancel() {
    if (!busy) onCancel()
  }

  // 默认焦点落在「取消」上，回车不会直接执行撤销。
  const containerRef = useModalFocus<HTMLDivElement>(requestCancel, {
    initialFocusSelector: '#revoke-app-cancel',
    escapeDisabled: busy,
  })

  return (
    <ModalOverlay onDismiss={requestCancel}>
      <HudPanel
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="revoke-app-title"
        aria-describedby="revoke-app-body revoke-app-scope"
        aria-busy={busy}
        tabIndex={-1}
        className="w-full max-w-lg"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Revoke Access</p>
            <h2 id="revoke-app-title" className="chenxing-h2 mt-2 break-words">撤销对“{name}”的授权？</h2>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={requestCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>
        <p id="revoke-app-body" className="chenxing-body mt-4">
          撤销后，该应用将无法再通过辰星通行证获取你的账户信息或保持登录，需要重新授权才能继续使用辰星通行证登录。
        </p>
        <div id="revoke-app-scope" className="mt-4">
          <Notice tone="warning">
            此操作仅撤销辰星通行证对该应用的授权，不会删除或解绑你在该应用中的账号、数据或设备。已签发的访问凭证可能在短时间内仍然有效。如需彻底解除绑定，请在该应用内操作或联系应用管理员。
          </Notice>
        </div>
        <div className="mt-6 flex flex-wrap justify-end gap-3">
          <Button id="revoke-app-cancel" type="button" variant="ghost" onClick={requestCancel} disabled={busy}>取消</Button>
          <Button type="button" variant="danger" icon="unlink" disabled={busy} onClick={() => { if (!busy) onConfirm() }}>
            {busy ? '撤销中…' : '撤销授权'}
          </Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}
