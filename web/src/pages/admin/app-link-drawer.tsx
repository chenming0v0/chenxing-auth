import { useState, type FormEvent } from 'react'
import { apiFetch, type AppLinkResponse } from '../../api'
import { Drawer } from '@chenxing/ui'
import { Button, Field, HudPanel, Notice, TextAreaField } from '@chenxing/ui'
import { useMutationLock } from '../../use-mutation-lock'

type FormState = {
  clientId: string
  packageName: string
  fingerprints: string
}
type FieldKey = keyof FormState
type FieldErrors = Partial<Record<FieldKey, string>>

const FIELD_ID: Record<FieldKey, string> = {
  clientId: 'app-link-client-id',
  packageName: 'app-link-package-name',
  fingerprints: 'app-link-fingerprints',
}
const FIELD_ORDER: FieldKey[] = ['clientId', 'packageName', 'fingerprints']

function parseFingerprints(raw: string): string[] {
  return raw
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function validate(form: FormState): FieldErrors {
  const errors: FieldErrors = {}
  if (!form.clientId.trim()) errors.clientId = '请填写 Client ID。'
  if (!form.packageName.trim()) errors.packageName = '请填写 Android 包名。'
  if (parseFingerprints(form.fingerprints).length === 0) errors.fingerprints = '请至少填写一条签名指纹。'
  return errors
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
  const [form, setForm] = useState<FormState>({
    clientId: editing?.client_id ?? '',
    packageName: editing?.package_name ?? '',
    fingerprints: editing?.sha256_cert_fingerprints.join('\n') ?? '',
  })
  const [errors, setErrors] = useState<FieldErrors>({})
  const [message, setMessage] = useState('')
  const { busy, run } = useMutationLock()
  const locked = Boolean(editing)

  function update(key: FieldKey, value: string) {
    setForm((current) => ({ ...current, [key]: value }))
    setErrors((current) => ({ ...current, [key]: undefined }))
  }

  function focusFirstError(nextErrors: FieldErrors) {
    const first = FIELD_ORDER.find((field) => nextErrors[field])
    if (first) document.getElementById(FIELD_ID[first])?.focus()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
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

  return (
    <Drawer
      title={editing ? '编辑软件链接' : '登记软件链接'}
      description={
        editing
          ? `覆盖「${editing.client_name}」已登记的包名和签名指纹。`
          : '登记后会写入公开的 assetlinks.json，Android 才能把回调交给这个 App。'
      }
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={busy}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button type="submit" icon="save" disabled={busy}>{busy ? '保存中…' : '保存声明'}</Button>
        </>
      }
    >
      {message ? <Notice tone="warning">{message}</Notice> : null}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">软件声明</p>
        <Field
          label="Client ID"
          id={FIELD_ID.clientId}
          icon="key-round"
          placeholder="在认证链接页复制"
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="none"
          value={form.clientId}
          onChange={(event) => update('clientId', event.target.value)}
          errorText={errors.clientId}
          hint={locked ? '这条声明绑定的软件，不能更改。' : '从「认证链接」页复制 Client ID。'}
          readOnly={locked}
        />
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
