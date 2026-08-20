import { useDrawerFocus } from '../../../components/drawer'
import { Button, Field, HudPanel, Icon, Notice, PasswordField, ToggleRow } from '../../../components/ui'
import { SelectField } from '../../../components/select'
import { useDirtyReport } from './panel'

export type ProviderForm = {
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

export function toInput(form: ProviderForm): OAuthProviderInput {
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
    email_verified_claim: form.email_verified_claim.trim(),
    client_auth_method: form.client_auth_method,
  }
  if (form.client_secret.trim()) input.client_secret = form.client_secret
  return input
}

type DialogProps = {
  /** null 表示创建；非 null 表示编辑该 provider（Slug 不可改） */
  editing: OAuthProviderSummary | null
  busy: boolean
  onSubmit: (form: ProviderForm) => void
  onClose: () => void
  onMessage: (message: string, tone?: 'success' | 'warning') => void
  /** 未保存草稿上报（#381）：与面板的 onDirtyChange 同约束，必须跨渲染稳定。 */
  onDirtyChange: (dirty: boolean) => void
}

/**
 * OAuth 提供商表单弹层：只负责表单状态、模板预设和提交前的本地校验。
 * 请求编排、部分成功状态与列表刷新都留在 OAuthProvidersPanel，
 * 这样「创建成功但启用失败」的重试动作不依赖弹层是否仍然挂载。
 */
export function OAuthProviderFormDialog({ editing, busy, onSubmit, onClose, onMessage, onDirtyChange }: DialogProps) {
  const [template, setTemplate] = useState('custom')
  const containerRef = useDrawerFocus(onClose, busy)
  const [form, setForm] = useState<ProviderForm>(() => toForm(editing))
  /* 挂载时的表单快照即基线：弹层由 key 驱动每次打开都重新挂载，因此基线天然按次刷新。 */
  const [initialForm] = useState<ProviderForm>(() => toForm(editing))
  const title = useMemo(() => (editing ? '编辑 OAuth 提供商' : '添加 OAuth 提供商'), [editing])

  /* 表单全部字段是标量，JSON 比较即可判定是否有未保存修改（#381）。 */
  const dirty = useMemo(() => JSON.stringify(form) !== JSON.stringify(initialForm), [form, initialForm])
  useDirtyReport(dirty, onDirtyChange)

  /** 用户主动关闭弹层时先确认未保存草稿；保存成功由父组件直接卸载，不经过这里。 */
  function requestClose() {
    if (dirty && !window.confirm('关闭后将丢失未保存的修改，确定关闭吗？')) return
    onClose()
  }

  function applyTemplate(next: string) {
    setTemplate(next)
    const preset = templates[next] || {}
    setForm((current) => ({ ...current, ...preset, client_secret: current.client_secret }))
  }

  function submit(event: FormEvent) {
    event.preventDefault()
    /* 防重入：保存请求在途时忽略重复提交（Issue #369）。busy 期间保存按钮已禁用，
       但 Enter 隐式提交仍会触发表单提交，这里与面板 save() 的入口守卫呼应。 */
    if (busy) return
    /* Client Secret 的必填语义只由这里承担，字段上不挂原生 required（Issue #403）：
       原生约束校验在 onSubmit 之前拦截，会用浏览器英文气泡遮蔽下面的中文警告；
       且编辑已配置的 provider 时留空表示「保持原值」，本来就无法用原生 required 表达。 */
    if (!editing) {
      if (!form.client_secret.trim()) {
        onMessage('创建提供商时必须填写 Client Secret。', 'warning')
        return
      }
    } else if (!editing.client_secret_configured && !form.client_secret.trim()) {
      onMessage('该提供商尚未配置 Client Secret，无法保存。请输入密钥。', 'warning')
      return
    }
    onSubmit(form)
  }

  return (
    <div className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center bg-[rgba(2,4,10,0.72)] px-4 py-8 backdrop-blur-md">
      <div ref={containerRef} className="relative z-[var(--chenxing-z-dialog)] w-full max-w-lg max-h-[90vh] overflow-y-auto" role="dialog" aria-modal="true" aria-labelledby="oauth-provider-dialog-title" tabIndex={-1}>
        <HudPanel as="form" className="w-full" onSubmit={submit}>
        <div className="flex items-start justify-between gap-4">
          <div>
            <h2 id="oauth-provider-dialog-title" className="chenxing-h2 flex items-center gap-2">
              <Icon name="link" className="text-[var(--chenxing-cyan)]" size={18} />
              {title}
            </h2>
            <p className="chenxing-caption mt-1.5">配置 OAuth 2.0 授权码流程 + UserInfo 的外部身份提供商</p>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={requestClose} disabled={busy}>
            <Icon name="x" size={16} />
          </button>
        </div>
        {/* busy 期间整体禁用表单字段（Issue #369）：fieldset 按规范禁用内部全部原生控件，
            SelectField 的 trigger 与 Switch 同为 button 也在其列，与其它设置面板一致。 */}
        <fieldset disabled={busy} className="mt-5 grid gap-4 border-0 p-0 m-0 min-w-0">
          {/* Issue #296：信任模型必须写在填表的地方。管理员在这里决定信任哪个外部身份源，
              而本平台对该身份源做了什么校验、没做什么校验，是这个决定的前提。 */}
          <Notice>
            信任模型：OAuth 2.0 + UserInfo。用户的 sub、email 和邮箱验证状态只来自该提供商的 UserInfo 响应；
            本平台不解析也不验证令牌响应中的 ID Token，因此请只接入 UserInfo 内容可信的提供商。
          </Notice>
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
          />
          {editing && !editing.client_secret_configured ? (
            <Notice tone="warning">尚未配置 Client Secret，用户通过该提供商登录将失败。请输入密钥后保存。</Notice>
          ) : null}
          <Field label="Authorization Endpoint *" value={form.authorization_endpoint} onChange={(event) => setForm({ ...form, authorization_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/authorize" required />
          <Field label="Token Endpoint *" value={form.token_endpoint} onChange={(event) => setForm({ ...form, token_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/token" required />
          <Field label="UserInfo Endpoint *" value={form.userinfo_endpoint} onChange={(event) => setForm({ ...form, userinfo_endpoint: event.target.value })} placeholder="https://idp.example.com/oauth/userinfo" required />
          <Field
            label="Scopes *"
            value={form.scopes}
            onChange={(event) => setForm({ ...form, scopes: event.target.value })}
            placeholder="openid profile email"
            hint="发往该提供商的 scope。可以包含 openid（多数提供商需要它才开放 UserInfo 端点），但本平台只用它换取可调用 UserInfo 的 access token，不会验证随之返回的 ID Token。"
            required
          />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Subject Claim" value={form.subject_claim} onChange={(event) => setForm({ ...form, subject_claim: event.target.value })} />
            <Field label="Email Claim" value={form.email_claim} onChange={(event) => setForm({ ...form, email_claim: event.target.value })} />
            <Field label="Name Claim" value={form.name_claim} onChange={(event) => setForm({ ...form, name_claim: event.target.value })} />
            <Field
              label="Email Verified Claim *"
              value={form.email_verified_claim}
              onChange={(event) => setForm({ ...form, email_verified_claim: event.target.value })}
              placeholder="email_verified"
              hint="必填，且必须指向布尔值。该身份源不返回邮箱验证状态时，本平台无法确认邮箱归属，会拒绝登录与自动建号。"
              required
            />
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
        </fieldset>
        <div className="chenxing-divider my-5" />
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <ToggleRow title="启用供应商" checked={form.enabled} disabled={busy} onChange={(enabled) => setForm({ ...form, enabled })} />
          <div className="flex items-center gap-3">
            <Button type="button" variant="ghost" onClick={requestClose} disabled={busy}>取消</Button>
            <Button type="submit" icon="save" disabled={busy}>保存</Button>
          </div>
        </div>
        </HudPanel>
      </div>
    </div>
  )
}
