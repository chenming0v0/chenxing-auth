import { useState, type FormEvent } from 'react'
import { Button, Drawer, Field, Notice, PasswordField } from '@chenxing/ui'
import type { AccountPortalAdminProvider, AccountPortalProviderInput } from '../../../account-portal-types'
import { useDirtyReport } from './panel'

export function AccountPortalForm({
  editing,
  busy,
  error,
  onSave,
  onClose,
  onDirtyChange,
}: {
  editing: AccountPortalAdminProvider | null
  busy: boolean
  error: string
  onSave: (value: AccountPortalProviderInput) => void
  onClose: () => void
  onDirtyChange: (dirty: boolean) => void
}) {
  const locked = editing?.identity_locked === true
  const [initial] = useState(() => ({
    display_name: editing?.display_name ?? '',
    issuer: editing?.issuer ?? '',
    client_id: editing?.client_id ?? '',
    client_secret: '',
  }))
  const [form, setForm] = useState(initial)
  const [validation, setValidation] = useState('')
  const dirty = JSON.stringify(form) !== JSON.stringify(initial)
  useDirtyReport(dirty, onDirtyChange)

  function close() {
    if (busy || (dirty && !window.confirm('关闭后将丢失未保存的修改，确定关闭吗？'))) return
    onClose()
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    const displayName = form.display_name.trim()
    const issuer = form.issuer.trim()
    const clientId = form.client_id.trim()
    if (!displayName || displayName.length > 128) {
      setValidation('显示名称须为 1 至 128 个字符。')
      return
    }
    let url: URL
    try { url = new URL(issuer) } catch { setValidation('issuer 必须是合法的 HTTPS origin。'); return }
    if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      setValidation('issuer 必须是 HTTPS origin，不能包含路径、查询或凭据。')
      return
    }
    if (!clientId || clientId.includes(':') || clientId.length > 512) {
      setValidation('client_id 不能为空、不能包含冒号，且不超过 512 字符。')
      return
    }
    if (!editing && (form.client_secret.length < 32 || form.client_secret.length > 512)) {
      setValidation('首次配置必须填写 32 至 512 字符的 client_secret。')
      return
    }
    if (editing && form.client_secret && (form.client_secret.length < 32 || form.client_secret.length > 512)) {
      setValidation('client_secret 须为 32 至 512 个字符，或留空保持原值。')
      return
    }
    setValidation('')
    onSave({
      display_name: displayName,
      issuer,
      client_id: clientId,
      expected_revision: editing?.revision ?? 0,
      ...(form.client_secret ? { client_secret: form.client_secret } : {}),
    })
  }

  return (
    <Drawer title={editing ? '编辑账号门户提供方' : '添加账号门户提供方'} onClose={close} onSubmit={submit} busy={busy}
      footer={<><Button variant="ghost" type="button" onClick={close} disabled={busy}>取消</Button>
        <Button icon="save" type="submit" disabled={busy}>{busy ? '保存中…' : '保存'}</Button></>}>
      <div className="flex flex-col gap-4">
        {validation || error ? <Notice tone="warning">{validation || error}</Notice> : null}
        {locked ? <Notice tone="info">存在有效绑定，issuer 与 client_id 已锁定。</Notice> : null}
        <Field id="portal-provider-name" label="显示名称" value={form.display_name} required maxLength={128}
          onChange={(event) => setForm({ ...form, display_name: event.target.value })} />
        <Field id="portal-provider-issuer" label="Issuer（HTTPS origin）" value={form.issuer} required type="url"
          disabled={locked} placeholder="https://provider.example.com"
          onChange={(event) => setForm({ ...form, issuer: event.target.value })} />
        <Field id="portal-provider-client" label="Client ID" value={form.client_id} required disabled={locked} maxLength={512}
          onChange={(event) => setForm({ ...form, client_id: event.target.value })} />
        <PasswordField id="portal-provider-secret" label="Client Secret" value={form.client_secret} autoComplete="new-password"
          placeholder={editing ? '已配置，留空保持原值' : '至少 32 字符'}
          onChange={(event) => setForm({ ...form, client_secret: event.target.value })} />
      </div>
    </Drawer>
  )
}
