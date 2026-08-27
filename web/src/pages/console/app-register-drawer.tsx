import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import {
  apiFetch,
  type ClientAuthMethod,
  type ClientCreateInput,
  type ClientInput,
  type OwnedOAuthClient,
  type RegisteredOwnedOAuthClient,
} from '../../api'
import { Drawer } from '@chenxing/ui'
import { SelectField } from '@chenxing/ui'
import { Button, Field, HudPanel, Icon, Notice, TextAreaField } from '@chenxing/ui'
import { DEFAULT_SELECTED_SCOPES } from '../../oauth-permissions'
import { useMutationLock } from '../../use-mutation-lock'
import {
  findInvalidRedirectUri,
  httpsUriProblem,
  newIdempotencyKey,
  REDIRECT_URI_RULE_MESSAGE,
} from './developer-shared'
import { PermissionChecklist } from './permission-checklist'
import { RedirectUriList, type RedirectUriListHandle } from './redirect-uri-list'

const NAME_MAX = 128
const DESCRIPTION_MAX = 512
const CONFIDENTIAL_AUTH_OPTIONS = [
  { value: 'client_secret_basic', label: 'HTTP Basic（client_secret_basic）' },
  { value: 'client_secret_post', label: '请求体（client_secret_post）' },
]

type AppKind = 'confidential' | 'public'

type FormState = {
  name: string
  description: string
  logoUri: string
  clientUri: string
  kind: AppKind
  authMethod: Exclude<ClientAuthMethod, 'none'>
  redirectUris: string[]
  scopes: string[]
}

type FieldKey = 'name' | 'description' | 'logoUri' | 'clientUri' | 'redirectUris' | 'scopes'
type FieldErrors = Partial<Record<FieldKey, string>>

const FIELD_ID: Record<FieldKey, string> = {
  name: 'app-register-name',
  description: 'app-register-description',
  logoUri: 'app-register-logo-uri',
  clientUri: 'app-register-client-uri',
  redirectUris: 'app-register-redirect-uris',
  scopes: 'app-register-scopes',
}
const FIELD_ORDER: FieldKey[] = ['name', 'description', 'logoUri', 'clientUri', 'redirectUris', 'scopes']

function emptyForm(): FormState {
  return {
    name: '',
    description: '',
    logoUri: '',
    clientUri: '',
    kind: 'confidential',
    authMethod: 'client_secret_basic',
    redirectUris: [],
    scopes: [...DEFAULT_SELECTED_SCOPES],
  }
}

function formFromClient(client: OwnedOAuthClient): FormState {
  return {
    ...emptyForm(),
    name: client.client_name,
    description: client.description ?? '',
    logoUri: client.logo_uri ?? '',
    clientUri: client.client_uri ?? '',
    kind: client.auth_method === 'none' ? 'public' : 'confidential',
    authMethod: client.auth_method === 'none' ? 'client_secret_basic' : client.auth_method,
    redirectUris: [...client.redirect_uris],
    scopes: [...client.scopes],
  }
}

function appMark(name: string): string {
  return (name || 'A').trim().slice(0, 1).toUpperCase() || 'A'
}

function optionalHttpsError(value: string, emptyOk: boolean): string | undefined {
  const trimmed = value.trim()
  if (!trimmed) return emptyOk ? undefined : '请填写 HTTPS 地址。'
  const reason = httpsUriProblem(trimmed)
  return reason ? `${reason}。` : undefined
}

function validate(form: FormState): FieldErrors {
  const errors: FieldErrors = {}
  const name = form.name.trim()
  if (!name) errors.name = '请填写应用名称。'
  else if (Array.from(name).length > NAME_MAX) errors.name = `应用名称最多 ${NAME_MAX} 个字符。`

  if (Array.from(form.description.trim()).length > DESCRIPTION_MAX) {
    errors.description = `应用描述最多 ${DESCRIPTION_MAX} 个字符。`
  }

  const logoError = optionalHttpsError(form.logoUri, true)
  if (logoError) errors.logoUri = logoError
  const homeError = optionalHttpsError(form.clientUri, true)
  if (homeError) errors.clientUri = homeError

  if (!form.redirectUris.length) errors.redirectUris = '请至少添加一个 Redirect URI。'
  else {
    const invalid = findInvalidRedirectUri(form.redirectUris)
    if (invalid) errors.redirectUris = `「${invalid.value}」${invalid.reason}。${REDIRECT_URI_RULE_MESSAGE}`
  }

  if (!form.scopes.length) errors.scopes = '请至少选择一项权限。'
  return errors
}

function authMethodOf(form: FormState): ClientAuthMethod {
  return form.kind === 'public' ? 'none' : form.authMethod
}

function previewCaption(form: FormState, creating: boolean, errors: FieldErrors): string {
  const description = form.description.trim()
  if (description) return description
  if (creating && form.clientUri.trim() && !errors.clientUri) return form.clientUri.trim()
  return '无 Logo 时，同意页使用名称首字'
}

export function AppRegisterDrawer({
  editing,
  onClose,
  onCreated,
  onUpdated,
}: {
  editing: OwnedOAuthClient | null
  onClose: () => void
  onCreated: (client: RegisteredOwnedOAuthClient) => void
  onUpdated: () => void
}) {
  const creating = editing === null
  const [form, setForm] = useState<FormState>(() => (editing ? formFromClient(editing) : emptyForm()))
  const [errors, setErrors] = useState<FieldErrors>({})
  const [message, setMessage] = useState('')
  const [logoFailed, setLogoFailed] = useState(false)
  const createIdempotencyRef = useRef<{ fingerprint: string; key: string } | null>(null)
  const redirectUrisRef = useRef<RedirectUriListHandle>(null)
  const { busy, run } = useMutationLock()
  const kindLabelId = useId()
  const previewLogo = form.logoUri.trim()

  useEffect(() => {
    setLogoFailed(false)
  }, [previewLogo])

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }))
    if (key in FIELD_ID) setErrors((current) => ({ ...current, [key as FieldKey]: undefined }))
  }

  function focusFirstError(nextErrors: FieldErrors) {
    const first = FIELD_ORDER.find((field) => nextErrors[field])
    if (first) document.getElementById(FIELD_ID[first])?.focus()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    const flushed = redirectUrisRef.current?.commitDraft()
    const redirectUris = flushed?.uris ?? form.redirectUris
    const nextForm = { ...form, redirectUris }
    const nextErrors = validate(nextForm)
    if (flushed?.error) {
      setErrors({ ...nextErrors, redirectUris: undefined })
      document.getElementById(FIELD_ID.redirectUris)?.focus()
      return
    }
    setErrors(nextErrors)
    if (Object.values(nextErrors).some(Boolean)) {
      focusFirstError(nextErrors)
      return
    }

    const input: ClientInput = {
      client_name: form.name.trim(),
      redirect_uris: redirectUris,
      scopes: form.scopes,
      logo_uri: form.logoUri.trim() || null,
      client_uri: form.clientUri.trim() || null,
      description: form.description.trim() || null,
    }
    await run(async () => {
      try {
        if (editing) {
          await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(editing.client_id)}`, {
            method: 'PUT',
            body: JSON.stringify(input),
          })
          onUpdated()
          return
        }
        const createInput: ClientCreateInput = { ...input, auth_method: authMethodOf(form) }
        const fingerprint = JSON.stringify(createInput)
        const pending = createIdempotencyRef.current
        const key = pending?.fingerprint === fingerprint ? pending.key : newIdempotencyKey()
        createIdempotencyRef.current = { fingerprint, key }
        const response = await apiFetch<RegisteredOwnedOAuthClient>('/api/v1/auth/oauth-clients', {
          method: 'POST',
          headers: { 'Idempotency-Key': key },
          body: JSON.stringify(createInput),
        })
        createIdempotencyRef.current = null
        onCreated(response)
      } catch (reason) {
        setMessage(reason instanceof Error ? reason.message : '应用保存失败。')
      }
    })
  }

  const showLogo = Boolean(previewLogo) && !logoFailed && !errors.logoUri

  return (
    <Drawer
      title={editing ? '编辑应用' : '注册新应用'}
      description="登记应用身份、回调地址，以及授权时向用户申请的权限。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={busy}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button type="submit" icon="save" disabled={busy}>{busy ? '保存中…' : editing ? '保存更新' : '创建应用'}</Button>
        </>
      }
    >
      {message ? <Notice tone="warning">{message}</Notice> : null}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">应用身份</p>
        <div className="flex items-center gap-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-3 py-3">
          {showLogo ? (
            <img
              src={previewLogo}
              alt=""
              className="h-14 w-14 shrink-0 rounded-2xl border border-[rgba(125,211,252,0.28)] object-contain bg-[rgba(4,8,16,0.55)]"
              onError={() => setLogoFailed(true)}
            />
          ) : (
            <span className="oauth-app-mark !mb-0 !h-14 !w-14 !text-2xl" aria-hidden="true">{appMark(form.name)}</span>
          )}
          <div className="min-w-0">
            <p className="chenxing-body truncate text-sm font-semibold">{form.name.trim() || '未命名应用'}</p>
            <p className="chenxing-caption mt-0.5 truncate">{previewCaption(form, creating, errors)}</p>
          </div>
        </div>
        <Field
          label="应用名称"
          id={FIELD_ID.name}
          icon="box"
          placeholder="例如：星尘控制台"
          value={form.name}
          onChange={(event) => update('name', event.target.value)}
          required
          errorText={errors.name}
          hint={`最多 ${NAME_MAX} 个字符，将出现在授权确认页。`}
        />
        <TextAreaField
          label="应用描述（选填）"
          id={FIELD_ID.description}
          placeholder="一句话说明这个应用是做什么的"
          value={form.description}
          onChange={(event) => update('description', event.target.value)}
          errorText={errors.description}
          rows={3}
          className="!min-h-20"
          hint={`最多 ${DESCRIPTION_MAX} 个字符，将出现在授权确认页。`}
        />
        <Field
          label="Logo URL（选填）"
          id={FIELD_ID.logoUri}
          icon="image"
          type="url"
          inputMode="url"
          placeholder="https://app.example.com/logo.png"
          value={form.logoUri}
          onChange={(event) => update('logoUri', event.target.value)}
          errorText={errors.logoUri}
          hint="仅 HTTPS 图片地址，不支持本地上传。同意页会展示这张图；留空则使用名称首字。"
        />
        <Field
          label="应用主页（选填）"
          id={FIELD_ID.clientUri}
          icon="globe"
          type="url"
          inputMode="url"
          placeholder="https://app.example.com"
          value={form.clientUri}
          onChange={(event) => update('clientUri', event.target.value)}
          errorText={errors.clientUri}
          hint="仅 HTTPS。用于同意页展示应用来源，不参与授权校验。"
        />
      </HudPanel>

      {creating ? (
        <HudPanel className="space-y-4 !p-5">
          <p className="chenxing-label !mb-0" id={kindLabelId}>应用类型</p>
          <div role="radiogroup" aria-labelledby={kindLabelId} className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              role="radio"
              aria-checked={form.kind === 'confidential'}
              className={`cx-factor-option ${form.kind === 'confidential' ? 'is-selected' : ''}`}
              onClick={() => update('kind', 'confidential')}
            >
              <Icon name="server" className="mt-0.5 shrink-0 text-[var(--chenxing-cyan)]" size={18} />
              <span>
                <span className="chenxing-body block text-sm font-semibold">机密客户端</span>
                <span className="chenxing-caption mt-0.5 block">有后端的 Web 应用，创建时签发 Client Secret。</span>
              </span>
            </button>
            <button
              type="button"
              role="radio"
              aria-checked={form.kind === 'public'}
              className={`cx-factor-option ${form.kind === 'public' ? 'is-selected' : ''}`}
              onClick={() => update('kind', 'public')}
            >
              <Icon name="layout-dashboard" className="mt-0.5 shrink-0 text-[var(--chenxing-cyan)]" size={18} />
              <span>
                <span className="chenxing-body block text-sm font-semibold">公开客户端</span>
                <span className="chenxing-caption mt-0.5 block">SPA / 原生应用，不签发 Secret，依赖 PKCE S256。</span>
              </span>
            </button>
          </div>
          {form.kind === 'confidential' ? (
            <SelectField
              label="令牌端点认证"
              icon="key-round"
              value={form.authMethod}
              onChange={(value) => update('authMethod', value as Exclude<ClientAuthMethod, 'none'>)}
              options={CONFIDENTIAL_AUTH_OPTIONS}
              hint="机密客户端在令牌端点出示 Secret 的方式。公开客户端固定为 none。"
            />
          ) : (
            <Notice tone="info">公开客户端不签发 Client Secret，换令牌时必须使用 PKCE。</Notice>
          )}
        </HudPanel>
      ) : (
        <HudPanel className="space-y-3 !p-5">
          <p className="chenxing-label !mb-0">应用类型</p>
          <p className="chenxing-body text-sm font-semibold">{form.kind === 'public' ? '公开客户端' : '机密客户端'}</p>
          <p className="chenxing-caption">认证方式在创建时确定，之后不能更改。公开客户端不签发 Secret。</p>
        </HudPanel>
      )}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">回调与权限</p>
        <RedirectUriList
          ref={redirectUrisRef}
          id={FIELD_ID.redirectUris}
          uris={form.redirectUris}
          onChange={(uris) => update('redirectUris', uris)}
          errorText={errors.redirectUris}
          disabled={busy}
        />
        <PermissionChecklist
          id={FIELD_ID.scopes}
          selected={form.scopes}
          onChange={(scopes) => update('scopes', scopes)}
          errorText={errors.scopes}
        />
      </HudPanel>
    </Drawer>
  )
}
