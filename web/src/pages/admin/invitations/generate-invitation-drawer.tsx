import { useState, type FormEvent } from 'react'
import { apiFetch, type CreatedInvitationCode } from '../../../api'
import { Drawer } from '../../../components/drawer'
import { Button, Field, HudPanel, Notice } from '../../../components/ui'
import { useMutationLock } from '../../../use-mutation-lock'
import { validateIntegerWithinRange } from '../settings/panel'
import { parseExpiresAt } from './helpers'

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'

type FieldKey = 'count' | 'maxUses' | 'expiresAt'
type FieldErrors = Partial<Record<FieldKey, string>>

const FIELD_ID: Record<FieldKey, string> = {
  count: 'generate-invite-count',
  maxUses: 'generate-invite-max-uses',
  expiresAt: 'generate-invite-expires-at',
}
const FIELD_ORDER: FieldKey[] = ['count', 'maxUses', 'expiresAt']

export function GenerateInvitationDrawer({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (codes: CreatedInvitationCode[]) => void
}) {
  const [count, setCount] = useState('1')
  const [maxUses, setMaxUses] = useState('1')
  const [label, setLabel] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [errors, setErrors] = useState<FieldErrors>({})
  const [message, setMessage] = useState('')
  const { busy, run } = useMutationLock()

  function clearError(key: FieldKey) {
    setErrors((current) => ({ ...current, [key]: undefined }))
  }

  function focusFirstError(next: FieldErrors) {
    const first = FIELD_ORDER.find((field) => next[field])
    if (first) document.getElementById(FIELD_ID[first])?.focus()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    const nextErrors: FieldErrors = {}
    const countResult = validateIntegerWithinRange(count, '生成数量', 100)
    const usesResult = validateIntegerWithinRange(maxUses, '每码可用次数', 10000)
    const expiresResult = parseExpiresAt(expiresAt)
    if ('error' in countResult) nextErrors.count = countResult.error
    if ('error' in usesResult) nextErrors.maxUses = usesResult.error
    if ('error' in expiresResult) nextErrors.expiresAt = expiresResult.error
    setErrors(nextErrors)
    if (nextErrors.count || nextErrors.maxUses || nextErrors.expiresAt) {
      focusFirstError(nextErrors)
      return
    }
    if ('error' in countResult || 'error' in usesResult || 'error' in expiresResult) return

    await run(async () => {
      try {
        const value = await apiFetch<CreatedInvitationCode[]>(CODES_PATH, {
          method: 'POST',
          body: JSON.stringify({
            count: countResult.value,
            max_uses: usesResult.value,
            expires_at: expiresResult.value,
            label: label.trim() || null,
          }),
        })
        onCreated(Array.isArray(value) ? value : [])
      } catch (reason) {
        setMessage(reason instanceof Error ? reason.message : '邀请码生成失败。')
      }
    })
  }

  return (
    <Drawer
      title="生成邀请码"
      description="明文只在生成后展示一次，离开后无法再看。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={busy}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button type="submit" icon="plus" disabled={busy}>{busy ? '生成中…' : '批量生成'}</Button>
        </>
      }
    >
      {message ? <Notice tone="warning">{message}</Notice> : null}
      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">批次设置</p>
        <Field
          label="生成数量"
          id={FIELD_ID.count}
          icon="layers"
          type="number"
          inputMode="numeric"
          value={count}
          onChange={(event) => { setCount(event.target.value); clearError('count') }}
          errorText={errors.count}
          hint="一次最多 100 个。"
        />
        <Field
          label="每码可用次数"
          id={FIELD_ID.maxUses}
          icon="ticket"
          type="number"
          inputMode="numeric"
          value={maxUses}
          onChange={(event) => { setMaxUses(event.target.value); clearError('maxUses') }}
          errorText={errors.maxUses}
          hint="每个码最多可使用 10000 次。"
        />
        <Field
          label="标签"
          id="generate-invite-label"
          value={label}
          onChange={(event) => setLabel(event.target.value)}
          placeholder="可选"
          hint="可选，用于区分批次。"
        />
        <Field
          label="过期时间"
          id={FIELD_ID.expiresAt}
          icon="calendar-clock"
          type="datetime-local"
          value={expiresAt}
          onChange={(event) => { setExpiresAt(event.target.value); clearError('expiresAt') }}
          errorText={errors.expiresAt}
          hint="留空表示不过期。"
        />
      </HudPanel>
    </Drawer>
  )
}
