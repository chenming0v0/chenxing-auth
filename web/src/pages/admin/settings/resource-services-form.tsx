import { useState, type FormEvent } from 'react'
import { Button, Drawer, Field, Notice, PasswordField, SelectField, TextAreaField } from '@chenxing/ui'
import type {
  ResourceServiceAdminProvider,
  ResourceServiceProviderInput,
  ResourceServiceScopeAccess,
} from '../../../resource-services-types'
import { useDirtyReport } from './panel'

/** 与后端 slug / scope 正则一致；scope 不得与基础 scope 冲突。 */
const SLUG_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/
const SCOPE_PATTERN = /^[a-z][a-z0-9_.:-]{0,127}$/
const RESERVED_SCOPES = new Set(['openid', 'profile', 'email', 'offline_access'])
const SCOPE_DESCRIPTION_MAX = 256
const CLIENT_ID_MAX = 255

export const SCOPE_ACCESS_OPTIONS: Array<{ value: ResourceServiceScopeAccess; label: string }> = [
  { value: 'restricted', label: '仅指定应用' },
  { value: 'public', label: '本站所有应用可申请' },
]

export function scopeAccessLabel(access: ResourceServiceScopeAccess): string {
  return SCOPE_ACCESS_OPTIONS.find((option) => option.value === access)?.label ?? access
}

export function defaultScope(slug: string): string {
  return `${slug}:access`
}

/** textarea 逐行 → client_id 列表：去空白、丢空行、去重。 */
export function parseClientIds(raw: string): string[] {
  const seen = new Set<string>()
  const result: string[] = []
  for (const line of raw.split(/\r?\n/)) {
    const value = line.trim()
    if (!value || seen.has(value)) continue
    seen.add(value)
    result.push(value)
  }
  return result
}

type FormState = {
  display_name: string
  slug: string
  issuer: string
  client_id: string
  client_secret: string
  scope: string
  scope_description: string
  scope_access: ResourceServiceScopeAccess
  allowed_client_ids: string
}

function initialForm(editing: ResourceServiceAdminProvider | null): FormState {
  return {
    display_name: editing?.display_name ?? '',
    slug: editing?.slug ?? '',
    issuer: editing?.issuer ?? '',
    client_id: editing?.client_id ?? '',
    client_secret: '',
    scope: editing?.scope ?? '',
    scope_description: editing?.scope_description ?? '',
    scope_access: editing?.scope_access ?? 'restricted',
    allowed_client_ids: editing?.allowed_client_ids.join('\n') ?? '',
  }
}

function validateIssuer(issuer: string): string | null {
  let url: URL
  try { url = new URL(issuer) } catch { return 'issuer 必须是合法的 HTTPS origin。' }
  if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
    return 'issuer 必须是 HTTPS origin，不能包含路径、查询或凭据。'
  }
  return null
}

function validateSecret(secret: string, editing: boolean): string | null {
  if (!editing && (secret.length < 32 || secret.length > 512)) return '首次配置必须填写 32 至 512 字符的 client_secret。'
  if (editing && secret && (secret.length < 32 || secret.length > 512)) return 'client_secret 须为 32 至 512 个字符，或留空保持原值。'
  return null
}

/** 返回第一条校验错误；通过时返回可提交的请求体。 */
function buildInput(form: FormState, editing: ResourceServiceAdminProvider | null): { error: string } | { input: ResourceServiceProviderInput } {
  const displayName = form.display_name.trim()
  const slug = form.slug.trim()
  const issuer = form.issuer.trim()
  const clientId = form.client_id.trim()
  const scope = form.scope.trim() || defaultScope(slug)
  const scopeDescription = form.scope_description.trim()
  const allowedClientIds = parseClientIds(form.allowed_client_ids)

  if (!displayName || displayName.length > 128) return { error: '显示名称须为 1 至 128 个字符。' }
  if (!SLUG_PATTERN.test(slug)) return { error: 'slug 须以小写字母开头，仅含 a-z、0-9、_、-，最长 64 字符。' }
  const issuerError = validateIssuer(issuer)
  if (issuerError) return { error: issuerError }
  if (!clientId || clientId.includes(':') || clientId.length > 512) return { error: 'client_id 不能为空、不能包含冒号，且不超过 512 字符。' }
  const secretError = validateSecret(form.client_secret, editing !== null)
  if (secretError) return { error: secretError }
  if (!SCOPE_PATTERN.test(scope)) return { error: 'scope 须以小写字母开头，仅含 a-z、0-9、_、.、:、-，最长 128 字符。' }
  if (RESERVED_SCOPES.has(scope)) return { error: 'scope 不能使用 openid、profile、email、offline_access 等基础权限名。' }
  if (scopeDescription.length > SCOPE_DESCRIPTION_MAX) return { error: `权限说明最多 ${SCOPE_DESCRIPTION_MAX} 个字符。` }
  const badClientId = allowedClientIds.find((value) => value.length > CLIENT_ID_MAX)
  if (badClientId) return { error: `应用 client_id 每项不超过 ${CLIENT_ID_MAX} 字符。` }

  return {
    input: {
      display_name: displayName,
      slug,
      issuer,
      client_id: clientId,
      scope,
      scope_description: scopeDescription,
      scope_access: form.scope_access,
      allowed_client_ids: allowedClientIds,
      expected_revision: editing?.revision ?? 0,
      ...(form.client_secret ? { client_secret: form.client_secret } : {}),
    },
  }
}

export function ResourceServiceForm({
  editing,
  busy,
  error,
  onSave,
  onClose,
  onDirtyChange,
}: {
  editing: ResourceServiceAdminProvider | null
  busy: boolean
  error: string
  onSave: (value: ResourceServiceProviderInput) => void
  onClose: () => void
  onDirtyChange: (dirty: boolean) => void
}) {
  const locked = editing?.identity_locked === true
  const [initial] = useState(() => initialForm(editing))
  const [form, setForm] = useState(initial)
  const [validation, setValidation] = useState('')
  const dirty = JSON.stringify(form) !== JSON.stringify(initial)
  useDirtyReport(dirty, onDirtyChange)

  function set<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }))
  }

  function close() {
    if (busy || (dirty && !window.confirm('关闭后将丢失未保存的修改，确定关闭吗？'))) return
    onClose()
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    const result = buildInput(form, editing)
    if ('error' in result) {
      setValidation(result.error)
      return
    }
    setValidation('')
    onSave(result.input)
  }

  const slugPreview = form.slug.trim()
  return (
    <Drawer title={editing ? '编辑资源服务' : '添加资源服务'} onClose={close} onSubmit={submit} busy={busy}
      footer={<><Button variant="ghost" type="button" onClick={close} disabled={busy}>取消</Button>
        <Button icon="save" type="submit" disabled={busy}>{busy ? '保存中…' : '保存'}</Button></>}>
      <div className="flex flex-col gap-4">
        {validation || error ? <Notice tone="warning">{validation || error}</Notice> : null}
        {locked ? <Notice tone="info">存在有效绑定，issuer 与 client_id 已锁定。</Notice> : null}
        <Field id="resource-service-name" label="显示名称" value={form.display_name} required maxLength={128}
          onChange={(event) => set('display_name', event.target.value)} />
        <Field id="resource-service-slug" label="Slug" value={form.slug} required maxLength={64} spellCheck={false}
          hint="小写字母开头，仅 a-z 0-9 _ -" placeholder="例如：demo-service"
          onChange={(event) => set('slug', event.target.value)} />
        <Field id="resource-service-issuer" label="Issuer（HTTPS origin）" value={form.issuer} required type="url"
          disabled={locked} placeholder="https://provider.example.com"
          onChange={(event) => set('issuer', event.target.value)} />
        <Field id="resource-service-client" label="Client ID" value={form.client_id} required disabled={locked} maxLength={512}
          onChange={(event) => set('client_id', event.target.value)} />
        <PasswordField id="resource-service-secret" label="Client Secret" value={form.client_secret} autoComplete="new-password"
          placeholder={editing ? '已配置，留空保持原值' : '至少 32 字符'}
          onChange={(event) => set('client_secret', event.target.value)} />
        <Field id="resource-service-scope" label="权限（scope）" value={form.scope} maxLength={128} spellCheck={false}
          placeholder={slugPreview ? defaultScope(slugPreview) : '留空取 <slug>:access'}
          hint="应用申请该资源服务时使用的 scope 名称；留空时取 <slug>:access。"
          onChange={(event) => set('scope', event.target.value)} />
        <Field id="resource-service-scope-description" label="权限说明" value={form.scope_description} maxLength={SCOPE_DESCRIPTION_MAX}
          hint="展示在应用注册与授权确认页，说明这项权限能访问什么。"
          onChange={(event) => set('scope_description', event.target.value)} />
        <SelectField label="开放范围" value={form.scope_access}
          onChange={(value) => set('scope_access', value as ResourceServiceScopeAccess)}
          options={SCOPE_ACCESS_OPTIONS} />
        <TextAreaField id="resource-service-allowed-clients" label="允许的应用 client_id" value={form.allowed_client_ids}
          placeholder="每行一个 client_id" spellCheck={false}
          hint="开放范围为“仅指定应用”时，只有这些应用可以申请该权限"
          onChange={(event) => set('allowed_client_ids', event.target.value)} />
      </div>
    </Drawer>
  )
}
