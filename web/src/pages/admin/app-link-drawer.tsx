import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AppLinkResponse, type ClientSummary } from '../../api'
import { Drawer } from '@chenxing/ui'
import { Button, CopyValue, Field, HudPanel, Notice, SelectField, TextAreaField } from '@chenxing/ui'
import { useMutationLock } from '../../use-mutation-lock'

type FormState = {
  clientId: string
  packageName: string
  fingerprints: string
}
type FieldKey = keyof FormState
type FieldErrors = Partial<Record<FieldKey, string>>
type ClientListState = 'loading' | 'ready' | 'empty' | 'failed'

const FIELD_ID: Record<FieldKey, string> = {
  clientId: 'app-link-client-id',
  packageName: 'app-link-package-name',
  fingerprints: 'app-link-fingerprints',
}
const FIELD_ORDER: FieldKey[] = ['clientId', 'packageName', 'fingerprints']
const CLIENTS_PATH = '/api/v1/admin/clients?limit=200'
const EMPTY_CLIENT_HINT = '还没有客户端。先到「接入应用」创建一个公开客户端。'

function parseFingerprints(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function validate(form: FormState): FieldErrors {
  const errors: FieldErrors = {}
  if (!form.clientId.trim()) errors.clientId = '请选择应用。'
  if (!form.packageName.trim()) errors.packageName = '请填写 Android 包名。'
  if (parseFingerprints(form.fingerprints).length === 0) errors.fingerprints = '请至少填写一条签名指纹。'
  return errors
}

function issuerFromDiscovery(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('issuer' in body)) return null
  const issuer = body.issuer
  if (typeof issuer !== 'string') return null
  const trimmed = issuer.trim().replace(/\/+$/, '')
  if (!/^https:\/\//i.test(trimmed)) return null
  return trimmed
}

function numericAppIdOf(client: Pick<ClientSummary, 'numeric_app_id'> | undefined): number | null {
  const value = client?.numeric_app_id
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function OfficialCallback({ numericAppId, issuer }: { numericAppId: number; issuer: string | null }) {
  const callbackPath = `/app/${numericAppId}/oauth/callback`
  const officialCallback = issuer ? `${issuer}${callbackPath}` : null
  return (
    <div className="space-y-3">
      <div className="min-w-0">
        <p className="chenxing-label">官方回调路径</p>
        <CopyValue value={callbackPath} ariaLabel="复制官方回调路径" />
      </div>
      {officialCallback ? (
        <div className="min-w-0">
          <p className="chenxing-label">官方完整回调 URL</p>
          <CopyValue value={officialCallback} ariaLabel="复制官方完整回调 URL" />
        </div>
      ) : (
        <p className="chenxing-caption">完整地址是配置中的 Issuer 加上这条路径。</p>
      )}
    </div>
  )
}

export function AppLinkDrawer({
  editing,
  onClose,
  onSaved,
}: {
  editing: AppLinkResponse | null
  onClose: () => void
  onSaved: () => void
}) {
  const locked = Boolean(editing)
  const [form, setForm] = useState<FormState>({
    clientId: editing?.client_id ?? '',
    packageName: editing?.package_name ?? '',
    fingerprints: editing?.sha256_cert_fingerprints.join('\n') ?? '',
  })
  const [errors, setErrors] = useState<FieldErrors>({})
  const [message, setMessage] = useState('')
  const [clients, setClients] = useState<ClientSummary[] | null>(locked ? [] : null)
  const [listError, setListError] = useState('')
  const [issuer, setIssuer] = useState<string | null>(null)
  const { busy, run } = useMutationLock()

  useEffect(() => {
    let active = true
    void fetch('/.well-known/openid-configuration')
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        if (active) setIssuer(issuerFromDiscovery(body))
      })
      .catch(() => {
        if (active) setIssuer(null)
      })
    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    if (locked) return
    let active = true
    void apiFetch<ClientSummary[]>(CLIENTS_PATH)
      .then((value) => {
        if (!active) return
        setClients(Array.isArray(value) ? value : [])
        setListError('')
      })
      .catch((reason: unknown) => {
        if (!active) return
        setClients([])
        setListError(reason instanceof Error ? reason.message : '应用列表加载失败。')
      })
    return () => {
      active = false
    }
  }, [locked])

  const listedClients = clients ?? []
  const listState: ClientListState = locked
    ? 'ready'
    : clients === null
      ? (listError ? 'failed' : 'loading')
      : listedClients.length
        ? 'ready'
        : listError
          ? 'failed'
          : 'empty'
  const selected = listedClients.find((client) => client.client_id === form.clientId)
  const numericAppId = editing ? editing.numeric_app_id : numericAppIdOf(selected)
  const canSubmit = locked || listState === 'ready'

  function update(key: FieldKey, value: string) {
    setForm((current) => ({ ...current, [key]: value }))
    setErrors((current) => ({ ...current, [key]: undefined }))
  }

  function focusFirstError(nextErrors: FieldErrors) {
    const first = FIELD_ORDER.find((field) => nextErrors[field])
    if (!first) return
    if (first === 'clientId') {
      document.querySelector<HTMLElement>(`#${FIELD_ID.clientId} [role="combobox"]`)?.focus()
      return
    }
    document.getElementById(FIELD_ID[first])?.focus()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!canSubmit) return
    setMessage('')
    const nextErrors = validate(form)
    setErrors(nextErrors)
    if (Object.values(nextErrors).some(Boolean)) {
      focusFirstError(nextErrors)
      return
    }

    const id = form.clientId.trim()
    const pkg = form.packageName.trim()
    const list = parseFingerprints(form.fingerprints)
    await run(async () => {
      try {
        await apiFetch<AppLinkResponse>(`/api/v1/admin/app-links/${encodeURIComponent(id)}`, {
          method: 'PUT',
          body: JSON.stringify({ package_name: pkg, sha256_cert_fingerprints: list }),
        })
        onSaved()
      } catch (reason) {
        setMessage(reason instanceof Error ? reason.message : '软件链接保存失败。')
      }
    })
  }

  const selectPlaceholder = listState === 'ready'
    ? '选择应用'
    : listState === 'loading'
      ? '正在加载应用…'
      : listState === 'empty'
        ? '没有可登记的应用'
        : '应用列表不可用'
  const selectHint = errors.clientId
    ?? (listState === 'empty' ? EMPTY_CLIENT_HINT : undefined)

  return (
    <Drawer
      title={editing ? '编辑软件链接' : '登记软件链接'}
      description={
        editing
          ? `覆盖「${editing.client_name}」已登记的包名和签名指纹。`
          : '选接入应用里的公开客户端，填 Android 包名和签名指纹。保存后本 Issuer 的 assetlinks.json 会发布这条声明，手机才会把回调交给这个 App。'
      }
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={busy}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button type="submit" icon="save" disabled={busy || !canSubmit}>{busy ? '保存中…' : '保存声明'}</Button>
        </>
      }
    >
      {listError || message ? <Notice tone="warning">{listError || message}</Notice> : null}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">软件声明</p>
        {locked && editing ? (
          <div>
            <p className="chenxing-label">官方应用</p>
            <p className="chenxing-body text-sm font-semibold">{editing.client_name}</p>
            <p className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{editing.client_id}</p>
            <p className="chenxing-caption mt-1.5">这条声明绑定的软件，不能更改。</p>
          </div>
        ) : (
          <div id={FIELD_ID.clientId}>
            <SelectField
              label="官方应用"
              icon="smartphone"
              value={form.clientId}
              onChange={(value) => update('clientId', value)}
              disabled={listState !== 'ready'}
              placeholder={selectPlaceholder}
              error={Boolean(errors.clientId)}
              options={listedClients.map((client) => ({
                value: client.client_id,
                label: `${client.client_name} · ${client.client_id}`,
              }))}
              hint={selectHint}
            />
          </div>
        )}
        {numericAppId !== null ? <OfficialCallback numericAppId={numericAppId} issuer={issuer} /> : null}
        <Field
          label="Android 包名"
          id={FIELD_ID.packageName}
          icon="box"
          placeholder="com.example.app"
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="none"
          value={form.packageName}
          onChange={(event) => update('packageName', event.target.value)}
          errorText={errors.packageName}
        />
        <TextAreaField
          label="SHA-256 签名指纹"
          id={FIELD_ID.fingerprints}
          placeholder="每行一条，支持 AA:BB 或 aabb 写法"
          spellCheck={false}
          value={form.fingerprints}
          onChange={(event) => update('fingerprints', event.target.value)}
          errorText={errors.fingerprints}
          hint="同包名可填多条：调试、发布、上传密钥轮换。"
        />
      </HudPanel>
    </Drawer>
  )
}
