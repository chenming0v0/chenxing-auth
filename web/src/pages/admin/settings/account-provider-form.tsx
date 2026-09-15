import { useState, type FormEvent } from 'react'
import { Button, Drawer, Field, Notice, PasswordField, SelectField, TextAreaField, ToggleRow } from '@chenxing/ui'
import type { AccountProviderUpdate, ManagedAccountProvider } from '../../../account-provider-types'
import { useDirtyReport } from './panel'

export function AccountProviderForm({
  editing, busy, error, onSave, onClose, onDirtyChange,
}: {
  editing: ManagedAccountProvider | null
  busy: boolean
  error: string
  onSave: (value: AccountProviderUpdate) => void
  onClose: () => void
  onDirtyChange: (dirty: boolean) => void
}) {
  const [initial] = useState(() => ({
    slug: editing?.slug ?? '', name: editing?.name ?? '',
    base_url: editing?.base_url ?? '', clients: editing?.allowed_client_ids.join('\n') ?? '',
    enabled: editing?.enabled ?? false, outbound: '', inbound: '',
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
    if (!/^[a-z][a-z0-9_-]{0,63}$/.test(form.slug)) {
      setValidation('供应商标识须以小写字母开头，仅含小写字母、数字、下划线或连字符。')
      return
    }
    if (!editing && (!form.outbound || !form.inbound)) {
      setValidation('首次配置必须填写两个独立的服务凭据。')
      return
    }
    for (const token of [form.outbound, form.inbound]) {
      if (token && (token.length < 32 || token.length > 4096 || /\s/.test(token))) {
        setValidation('服务凭据须为 32 至 4096 个字符且不含空白。')
        return
      }
    }
    if (form.outbound && form.outbound === form.inbound) {
      setValidation('两个调用方向不能使用相同的服务凭据。')
      return
    }
    let url: URL
    try { url = new URL(form.base_url.trim()) } catch { setValidation('请填写有效的 HTTPS 服务地址。'); return }
    if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
      setValidation('服务地址必须为 HTTPS 根地址，不能包含路径、查询参数或凭据。')
      return
    }
    const clients = form.clients.split(/[\s,]+/).filter(Boolean)
    if (!clients.length || clients.length > 100 || new Set(clients).size !== clients.length) {
      setValidation('请填写 1 至 100 个不重复的 OAuth Client ID。')
      return
    }
    setValidation('')
    onSave({
      slug: form.slug, name: form.name.trim(), adapter: 'cltermux',
      base_url: url.toString(), enabled: form.enabled, allowed_client_ids: clients,
      expected_version: editing?.version ?? 0,
      ...(form.outbound ? { outbound_token: form.outbound } : {}),
      ...(form.inbound ? { inbound_token: form.inbound } : {}),
    })
  }
  return (
    <Drawer title={editing ? '编辑特殊供应商' : '添加特殊供应商'} onClose={close} onSubmit={submit} busy={busy}
      footer={<><Button variant="ghost" type="button" onClick={close} disabled={busy}>取消</Button>
        <Button icon="save" type="submit" disabled={busy}>{busy ? '保存中…' : '保存'}</Button></>}>
      <div className="flex flex-col gap-4">
        {validation || error ? <Notice tone="warning">{validation || error}</Notice> : null}
        <SelectField label="供应商类型" value="cltermux" options={[{ value: 'cltermux', label: 'CLtermux · 公钥/私钥绑定' }]} onChange={() => {}} />
        <Field id="account-provider-name" label="显示名称" value={form.name} required maxLength={128}
          onChange={(event) => setForm({ ...form, name: event.target.value })} />
        <Field id="account-provider-slug" label="供应商标识" value={form.slug} required disabled={!!editing} maxLength={64}
          placeholder="cltermux-test" onChange={(event) => setForm({ ...form, slug: event.target.value })} />
        <Field id="account-provider-url" label="HTTPS 服务地址" value={form.base_url} required type="url" maxLength={2048}
          placeholder="https://cltermux.example.com" onChange={(event) => setForm({ ...form, base_url: event.target.value })} />
        <PasswordField id="account-provider-outbound" label="辰星 → 供应商 Token"
          value={form.outbound} autoComplete="new-password"
          placeholder={editing?.outbound_token_configured ? '已配置，留空保持原值' : '独立随机凭据，至少 32 字符'}
          onChange={(event) => setForm({ ...form, outbound: event.target.value })} />
        <PasswordField id="account-provider-inbound" label="供应商 → 辰星 Token"
          value={form.inbound} autoComplete="new-password"
          placeholder={editing?.inbound_token_configured ? '已配置，留空保持原值' : '另一个独立随机凭据'}
          onChange={(event) => setForm({ ...form, inbound: event.target.value })} />
        <TextAreaField id="account-provider-clients" label="允许的 OAuth Client ID" value={form.clients} required
          placeholder="每行一个 Client ID" onChange={(event) => setForm({ ...form, clients: event.target.value })} />
        <ToggleRow title="启用供应商" checked={form.enabled}
          onChange={(enabled) => setForm({ ...form, enabled })} />
      </div>
    </Drawer>
  )
}
