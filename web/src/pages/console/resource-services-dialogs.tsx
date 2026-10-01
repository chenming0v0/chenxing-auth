import { useState, type FormEvent } from 'react'
import { Button, Field, HudPanel, Icon, ModalOverlay, Notice, PasswordField, useModalFocus } from '@chenxing/ui'
import type { ResourceServicePublicProvider } from '../../resource-services-types'

export function BindResourceServiceDialog({
  provider,
  busy,
  error,
  onCancel,
  onSubmit,
}: {
  provider: ResourceServicePublicProvider
  busy: boolean
  error: string | null
  onCancel: () => void
  onSubmit: (identifier: string, secret: string) => Promise<boolean>
}) {
  const [identifier, setIdentifier] = useState('')
  const [secret, setSecret] = useState('')
  const [fieldError, setFieldError] = useState<string | null>(null)
  const identifierId = 'resource-service-bind-identifier'
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: `#${identifierId}`,
    escapeDisabled: busy,
  })

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    if (!identifier.trim() || !secret.trim()) {
      setFieldError('请填写全部凭据。')
      return
    }
    setFieldError(null)
    if (await onSubmit(identifier.trim(), secret.trim())) onCancel()
  }

  const IdentifierField = provider.identifier_sensitive ? PasswordField : Field
  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel
        ref={containerRef}
        as="form"
        role="dialog"
        aria-modal="true"
        aria-labelledby="resource-service-bind-title"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-lg"
        onSubmit={(event) => { void handleSubmit(event) }}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Resource Services</p>
            <h2 id="resource-service-bind-title" className="chenxing-h2 mt-2">绑定 {provider.display_name}</h2>
            <p className="chenxing-caption mt-2">凭据只用于本次校验，平台不会保存。授权只读，有效期由资源服务决定。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>
        <div className="mt-5 space-y-4">
          {error ? <Notice tone="warning">{error}</Notice> : null}
          <IdentifierField
            id={identifierId}
            label={provider.identifier_label}
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
            errorText={fieldError && !identifier.trim() ? fieldError : undefined}
            disabled={busy}
            autoComplete="off"
          />
          <PasswordField
            id="resource-service-bind-secret"
            label={provider.secret_label}
            value={secret}
            onChange={(event) => setSecret(event.target.value)}
            errorText={fieldError && !secret.trim() ? fieldError : undefined}
            disabled={busy}
            autoComplete="new-password"
          />
        </div>
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="ghost" type="button" onClick={onCancel} disabled={busy}>取消</Button>
          <Button icon="link" type="submit" disabled={busy}>{busy ? '绑定中…' : '确认绑定'}</Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}

export function UnlinkResourceServiceDialog({
  name,
  isCltermux,
  busy,
  error,
  onCancel,
  onSubmit,
}: {
  name: string
  isCltermux: boolean
  busy: boolean
  error: string | null
  onCancel: () => void
  onSubmit: () => Promise<boolean>
}) {
  const containerRef = useModalFocus<HTMLDivElement>(onCancel, { escapeDisabled: busy })
  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel
        ref={containerRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="resource-service-unlink-title"
        aria-describedby="resource-service-unlink-description"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-md"
      >
        <h2 id="resource-service-unlink-title" className="chenxing-h2">解除账号关联？</h2>
        <p className="chenxing-body mt-2">将解除与 {name} 账号的关联。</p>
        <p id="resource-service-unlink-description" className="chenxing-caption mt-2">仅解除辰星与该账号的授权关联{isCltermux ? '，不会解除设备绑定。设备绑定只能由管理员重置。' : '。'}</p>
        {error ? <div className="mt-4"><Notice tone="warning">{error}</Notice></div> : null}
        <div className="mt-6 flex justify-end gap-2">
          <Button variant="ghost" type="button" onClick={onCancel} disabled={busy}>取消</Button>
          <Button variant="danger" icon="unlink" type="button" disabled={busy} onClick={() => { void onSubmit().then((done) => { if (done) onCancel() }) }}>
            {busy ? '正在解除账号关联…' : '解除账号关联'}
          </Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}
