import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { apiFetch, type OAuthProviderInput, type OAuthProviderSummary } from '../../../api'
import { Badge, Button, EmptyState, Field, HudPanel, Icon, Notice, PasswordField, ToggleRow } from '../../../components/ui'
import { SelectField } from '../../../components/select'

type ProviderForm = {
  name: string
  slug: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  client_id: string
  client_secret: string
  scopes: string
  subject_claim: string
  email_claim: string
  name_claim: string
  email_verified_claim: string
  client_auth_method: 'basic' | 'request_body'
  enabled: boolean
}

const emptyForm: ProviderForm = {
  name: '',
  slug: '',
  authorization_endpoint: '',
  token_endpoint: '',
  userinfo_endpoint: '',
  client_id: '',
  client_secret: '',
  scopes: 'openid profile email',
  subject_claim: 'sub',
  email_claim: 'email',
  name_claim: 'name',
  email_verified_claim: 'email_verified',
  client_auth_method: 'basic',
  enabled: true,
}

const templates: Record<string, Partial<ProviderForm>> = {
  custom: {},
  github_enterprise: {
    name: 'GitHub Enterprise',
    slug: 'github-enterprise',
    authorization_endpoint: 'https://github.example.com/login/oauth/authorize',
    token_endpoint: 'https://github.example.com/login/oauth/access_token',
    userinfo_endpoint: 'https://github.example.com/api/v3/user',
    scopes: 'read:user user:email',
    subject_claim: 'id',
    email_claim: 'email',
    name_claim: 'name',
    email_verified_claim: '',
  },
  gitlab: {
    name: 'GitLab',
    slug: 'gitlab',
    authorization_endpoint: 'https://gitlab.example.com/oauth/authorize',
    token_endpoint: 'https://gitlab.example.com/oauth/token',
    userinfo_endpoint: 'https://gitlab.example.com/oauth/userinfo',
    scopes: 'openid profile email',
  },
  gitea: {
    name: 'Gitea',
    slug: 'gitea',
    authorization_endpoint: 'https://gitea.example.com/login/oauth/authorize',
    token_endpoint: 'https://gitea.example.com/login/oauth/access_token',
    userinfo_endpoint: 'https://gitea.example.com/login/oauth/userinfo',
    scopes: 'openid profile email',
  },
  keycloak: {
    name: 'Keycloak',
    slug: 'keycloak',
    authorization_endpoint: 'https://idp.example.com/realms/example/protocol/openid-connect/auth',
    token_endpoint: 'https://idp.example.com/realms/example/protocol/openid-connect/token',
    userinfo_endpoint: 'https://idp.example.com/realms/example/protocol/openid-connect/userinfo',
    scopes: 'openid profile email',
  },
}

function splitScopes(value: string): string[] {
  return value.replace(/,/g, ' ').split(/\s+/).map((item) => item.trim()).filter(Boolean)
}

function toForm(provider?: OAuthProviderSummary | null): ProviderForm {
  if (!provider) return { ...emptyForm }
  return {
    name: provider.name,
    slug: provider.slug,
    authorization_endpoint: provider.authorization_endpoint,
    token_endpoint: provider.token_endpoint,
    userinfo_endpoint: provider.userinfo_endpoint,
    client_id: provider.client_id,
    client_secret: '',
    scopes: provider.scopes.join(' '),
    subject_claim: provider.subject_claim,
    email_claim: provider.email_claim,
    name_claim: provider.name_claim || '',
    email_verified_claim: provider.email_verified_claim || '',
    client_auth_method: provider.client_auth_method === 'request_body' ? 'request_body' : 'basic',
    enabled: provider.status === 'active',
  }
}

function toInput(form: ProviderForm): OAuthProviderInput {
  const input: OAuthProviderInput = {
    name: form.name.trim(),
    slug: form.slug.trim(),
    authorization_endpoint: form.authorization_endpoint.trim(),
    token_endpoint: form.token_endpoint.trim(),
    userinfo_endpoint: form.userinfo_endpoint.trim(),
    client_id: form.client_id.trim(),
    scopes: splitScopes(form.scopes),
    subject_claim: form.subject_claim.trim() || 'sub',
    email_claim: form.email_claim.trim() || 'email',
    name_claim: form.name_claim.trim() || null,
    email_verified_claim: form.email_verified_claim.trim() || null,
    client_auth_method: form.client_auth_method,
  }
  if (form.client_secret.trim()) input.client_secret = form.client_secret
  return input
}

export function OAuthProvidersPanel({ onMessage }: { onMessage: (message: string, tone?: 'success' | 'warning') => void }) {
  const [providers, setProviders] = useState<OAuthProviderSummary[] | null>(null)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<OAuthProviderSummary | null>(null)
  const [template, setTemplate] = useState('custom')
  const [form, setForm] = useState<ProviderForm>(emptyForm)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const title = useMemo(() => (editing ? '编辑 OAuth 提供商' : '添加 OAuth 提供商'), [editing])

  async function load() {
    setLoading(true)
    try {
      setProviders(await apiFetch<OAuthProviderSummary[]>('/api/v1/admin/oauth/providers'))
    } catch (reason) {
      setProviders([])
      onMessage(reason instanceof Error ? reason.message : 'OAuth 提供商加载失败。', 'warning')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  function openCreate() {
    setEditing(null)
    setTemplate('custom')
    setForm({ ...emptyForm })
    setOpen(true)
  }

  function openEdit(provider: OAuthProviderSummary) {
    setEditing(provider)
    setTemplate('custom')
    setForm(toForm(provider))
    setOpen(true)
  }

  function applyTemplate(next: string) {
    setTemplate(next)
    const preset = templates[next] || {}
    setForm((current) => ({ ...current, ...preset, client_secret: current.client_secret }))
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (editing && !editing.client_secret_configured && !form.client_secret.trim()) {
      onMessage('该提供商尚未配置 Client Secret，无法保存。请输入密钥。', 'warning')
      return
    }
    setBusy(true)
    try {
      if (editing) {
        await apiFetch<void>(`/api/v1/admin/oauth/providers/${encodeURIComponent(editing.slug)}`, {
          method: 'PUT',
          body: JSON.stringify(toInput(form)),
        })
        const currentActive = editing.status === 'active'
        if (form.enabled !== currentActive) {
          await apiFetch<void>(`/api/v1/admin/oauth/providers/${encodeURIComponent(editing.slug)}/${form.enabled ? 'enable' : 'disable'}`, {
            method: 'POST',
          })
        }
        onMessage('OAuth 提供商已更新。')
      } else {
        if (!form.client_secret.trim()) {
          onMessage('创建提供商时必须填写 Client Secret。', 'warning')
          setBusy(false)
          return
        }
        const created = await apiFetch<OAuthProviderSummary>('/api/v1/admin/oauth/providers', {
          method: 'POST',
          body: JSON.stringify(toInput(form)),
        })
        if (form.enabled) {
          await apiFetch<void>(`/api/v1/admin/oauth/providers/${encodeURIComponent(created.slug)}/enable`, { method: 'POST' })
        }
        onMessage('OAuth 提供商已创建。')
      }
      setOpen(false)
      await load()
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : 'OAuth 提供商保存失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  async function toggleStatus(provider: OAuthProviderSummary) {
    const action = provider.status === 'active' ? 'disable' : 'enable'
    if (!window.confirm(`确认${action === 'disable' ? '禁用' : '启用'} ${provider.name} 吗？`)) return
    setBusy(true)
    try {
      await apiFetch<void>(`/api/v1/admin/oauth/providers/${encodeURIComponent(provider.slug)}/${action}`, { method: 'POST' })
      onMessage(`已${action === 'disable' ? '禁用' : '启用'} ${provider.name}。`)
      await load()
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : 'OAuth 提供商状态更新失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <HudPanel>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h2 className="chenxing-h2 flex items-center gap-2">
              <Icon name="link" className="text-[var(--chenxing-cyan)]" size={18} />
              自定义 OAuth 提供商
            </h2>
            <p className="chenxing-caption mt-1.5">支持 GitHub Enterprise、GitLab、Gitea、Keycloak 等兼容 OAuth 2.0 的身份提供商</p>
          </div>
          <Button icon="plus" onClick={openCreate}>添加 OAuth 提供商</Button>
        </div>
        <div className="mt-5 overflow-x-auto rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)]">
          <table className="w-full min-w-[820px] text-left">
            <thead>
              <tr className="border-b border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.5)]">
                <th className="chenxing-label px-4 py-3">图标</th>
                <th className="chenxing-label px-4 py-3">名称</th>
                <th className="chenxing-label px-4 py-3">Slug</th>
                <th className="chenxing-label px-4 py-3">状态</th>
                <th className="chenxing-label px-4 py-3">Client ID</th>
                <th className="chenxing-label px-4 py-3">Client Secret</th>
                <th className="chenxing-label px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {providers?.map((provider) => (
                <tr key={provider.slug} className="border-t border-[var(--chenxing-border)]">
                  <td className="px-4 py-3">
                    <span className="inline-flex h-9 w-9 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(56,189,248,0.1)]">
                      <Icon name="shield" className="text-[var(--chenxing-cyan)]" size={16} />
                    </span>
                  </td>
                  <td className="chenxing-body px-4 py-3 text-sm">{provider.name}</td>
                  <td className="chenxing-mono px-4 py-3 text-xs text-[var(--chenxing-muted-foreground)]">{provider.slug}</td>
                  <td className="px-4 py-3">
                    <Badge tone={provider.status === 'active' ? 'success' : 'warning'}>
                      {provider.status === 'active' ? '已启用' : '已禁用'}
                    </Badge>
                  </td>
                  <td className="chenxing-mono px-4 py-3 text-xs text-[var(--chenxing-muted-foreground)]">
                    {provider.client_id.length > 18 ? `${provider.client_id.slice(0, 18)}...` : provider.client_id}
                  </td>
                  <td className="px-4 py-3">
                    {provider.client_secret_configured ? (
                      <Badge tone="success">
                        <Icon name="check" size={12} />
                        已配置
                      </Badge>
                    ) : (
                      <Badge tone="warning">
                        <Icon name="alert-triangle" size={12} />
                        未配置
                      </Badge>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-3">
                      <button type="button" className="chenxing-link" onClick={() => openEdit(provider)}>编辑</button>
                      <button type="button" className="chenxing-link" style={{ color: 'var(--chenxing-error)' }} onClick={() => void toggleStatus(provider)} disabled={busy}>
                        {provider.status === 'active' ? '禁用' : '启用'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {loading ? <div className="mt-5"><Notice>正在加载 OAuth 提供商。</Notice></div> : null}
        {!loading && !providers?.length ? (
          <div className="mt-6">
            <EmptyState icon="link" title="尚未配置外部身份提供商" description="添加兼容 OAuth 2.0 的发行者后，用户可在登录页选择外部身份。" action={<Button icon="plus" onClick={openCreate}>添加 OAuth 提供商</Button>} />
          </div>
        ) : null}
      </HudPanel>

      {open ? (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-[rgba(2,4,10,0.72)] px-4 py-8 backdrop-blur-md">
          <HudPanel as="form" className="w-full max-w-lg max-h-[90vh] overflow-y-auto" onSubmit={save}>
            <div className="flex items-start justify-between gap-4">
              <div>
                <h2 className="chenxing-h2 flex items-center gap-2">
                  <Icon name="link" className="text-[var(--chenxing-cyan)]" size={18} />
                  {title}
                </h2>
                <p className="chenxing-caption mt-1.5">配置兼容 OAuth 2.0 的外部身份提供商</p>
              </div>
              <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={() => setOpen(false)}>
                <Icon name="x" size={16} />
              </button>
            </div>
            <div className="mt-5 grid gap-4">
              {!editing ? (
                <SelectField
                  label="预设模板"
                  value={template}
                  onChange={applyTemplate}
                  options={[
                    { value: 'custom', label: '自定义' },
                    { value: 'github_enterprise', label: 'GitHub Enterprise' },
                    { value: 'gitlab', label: 'GitLab' },
                    { value: 'gitea', label: 'Gitea' },
                    { value: 'keycloak', label: 'Keycloak' },
                  ]}
                />
              ) : null}
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="显示名称 *" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如: 企业 GitLab" required />
                <Field label="Slug *" value={form.slug} onChange={(event) => setForm({ ...form, slug: event.target.value })} placeholder="例如: gitlab" required disabled={Boolean(editing)} />
              </div>
              <Field label="Client ID *" value={form.client_id} onChange={(event) => setForm({ ...form, client_id: event.target.value })} placeholder="从提供商控制台复制" required />
              <PasswordField
                label={editing ? (editing.client_secret_configured ? 'Client Secret' : 'Client Secret *') : 'Client Secret *'}
                value={form.client_secret}
                onChange={(event) => setForm({ ...form, client_secret: event.target.value })}
                placeholder={editing ? (editing.client_secret_configured ? '留空保持不变，输入新值替换' : '尚未配置，请输入 Client Secret') : '仅保存时使用，保存后不再回显'}
                hint={editing ? (editing.client_secret_configured ? '已配置 Client Secret：留空保持不变，输入新值替换。保存后不会回显明文。' : '当前未配置 Client Secret，登录该提供商将失败。请输入密钥，保存后不会回显明文。') : '密钥将加密存储，保存后不会回显明文。'}
                required={!editing || !editing.client_secret_configured}
              />
              {editing && !editing.client_secret_configured ? (
                <Notice tone="warning">尚未配置 Client Secret，用户通过该提供商登录将失败。请输入密钥后保存。</Notice>
              ) : null}
              <Field label="Authorization Endpoint *" value={form.authorization_endpoint} onChange={(event) => setForm({ ...form, authorization_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/authorize" required />
              <Field label="Token Endpoint *" value={form.token_endpoint} onChange={(event) => setForm({ ...form, token_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/token" required />
              <Field label="UserInfo Endpoint *" value={form.userinfo_endpoint} onChange={(event) => setForm({ ...form, userinfo_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/userinfo" required />
              <Field label="Scopes *" value={form.scopes} onChange={(event) => setForm({ ...form, scopes: event.target.value })} placeholder="openid profile email" required />
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Subject Claim" value={form.subject_claim} onChange={(event) => setForm({ ...form, subject_claim: event.target.value })} />
                <Field label="Email Claim" value={form.email_claim} onChange={(event) => setForm({ ...form, email_claim: event.target.value })} />
                <Field label="Name Claim" value={form.name_claim} onChange={(event) => setForm({ ...form, name_claim: event.target.value })} />
                <Field label="Email Verified Claim" value={form.email_verified_claim} onChange={(event) => setForm({ ...form, email_verified_claim: event.target.value })} />
              </div>
              <SelectField
                label="Client Auth Method"
                value={form.client_auth_method}
                onChange={(value) => setForm({ ...form, client_auth_method: value as 'basic' | 'request_body' })}
                options={[
                  { value: 'basic', label: 'basic' },
                  { value: 'request_body', label: 'request_body' },
                ]}
              />
              {editing?.callback_uri ? <Field label="Callback URI" value={editing.callback_uri} readOnly /> : null}
            </div>
            <div className="chenxing-divider my-5" />
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <ToggleRow title="启用供应商" checked={form.enabled} onChange={(enabled) => setForm({ ...form, enabled })} />
              <div className="flex items-center gap-3">
                <Button type="button" variant="ghost" onClick={() => setOpen(false)}>取消</Button>
                <Button type="submit" icon="save" disabled={busy}>保存</Button>
              </div>
            </div>
          </HudPanel>
        </div>
      ) : null}
    </>
  )
}
