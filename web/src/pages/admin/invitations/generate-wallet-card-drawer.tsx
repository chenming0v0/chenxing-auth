import { useState, type FormEvent } from 'react'
import { apiFetch, type CreatedWalletRedemptionCard } from '../../../api'
import { Drawer } from '@chenxing/ui'
import { Button, Field, HudPanel, Notice } from '@chenxing/ui'
import { useMutationLock } from '../../../use-mutation-lock'
import { validateIntegerWithinRange } from '../settings/panel'
import { parseExpiresAt } from './helpers'

const CARDS_PATH = '/api/v1/admin/wallet/redemption-codes'

type FieldKey = 'points' | 'count' | 'maxUses' | 'expiresAt'
type FieldErrors = Partial<Record<FieldKey, string>>

const FIELD_ID: Record<FieldKey, string> = {
  points: 'generate-wallet-points',
  count: 'generate-wallet-count',
  maxUses: 'generate-wallet-max-uses',
  expiresAt: 'generate-wallet-expires-at',
}
const FIELD_ORDER: FieldKey[] = ['points', 'count', 'maxUses', 'expiresAt']

export function GenerateWalletCardDrawer({
  onClose,
  onCreated,
}: {
  onClose: () => void
  onCreated: (cards: CreatedWalletRedemptionCard[]) => void
}) {
  const [points, setPoints] = useState('')
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
    const pointsResult = validateIntegerWithinRange(points, '面值', Number.MAX_SAFE_INTEGER)
    const countResult = validateIntegerWithinRange(count, '生成数量', 100)
    const usesResult = validateIntegerWithinRange(maxUses, '每码可用次数', 10000)
    const expiresResult = parseExpiresAt(expiresAt)
    if ('error' in pointsResult) nextErrors.points = pointsResult.error
    if ('error' in countResult) nextErrors.count = countResult.error
    if ('error' in usesResult) nextErrors.maxUses = usesResult.error
    if ('error' in expiresResult) nextErrors.expiresAt = expiresResult.error
    setErrors(nextErrors)
    if (nextErrors.points || nextErrors.count || nextErrors.maxUses || nextErrors.expiresAt) {
      focusFirstError(nextErrors)
      return
    }
    if ('error' in pointsResult || 'error' in countResult || 'error' in usesResult || 'error' in expiresResult) return

    await run(async () => {
      try {
        const value = await apiFetch<CreatedWalletRedemptionCard[]>(CARDS_PATH, {
          method: 'POST',
          body: JSON.stringify({
            points: pointsResult.value,
            count: countResult.value,
            max_uses: usesResult.value,
            label: label.trim() || null,
            expires_at: expiresResult.value,
          }),
        })
        onCreated(Array.isArray(value) ? value : [])
      } catch (reason) {
        setMessage(reason instanceof Error ? reason.message : '兑换卡生成失败。')
      }
    })
  }

  return (
    <Drawer
      title="生成兑换卡"
      description="明文只在生成后展示一次，离开后无法再看。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={busy}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={busy}>取消</Button>
          <Button type="submit" icon="plus" disabled={busy}>{busy ? '生成中…' : '生成兑换卡'}</Button>
        </>
      }
    >
      {message ? <Notice tone="warning">{message}</Notice> : null}
      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">批次设置</p>
        <Field
          label="面值（辰星点）"
          id={FIELD_ID.points}
          icon="zap"
          type="number"
          inputMode="numeric"
          value={points}
          onChange={(event) => { setPoints(event.target.value); clearError('points') }}
          errorText={errors.points}
          hint="每个兑换码到账的辰星点，必须是大于 0 的整数。"
        />
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
          icon="wallet"
          type="number"
          inputMode="numeric"
          value={maxUses}
          onChange={(event) => { setMaxUses(event.target.value); clearError('maxUses') }}
          errorText={errors.maxUses}
          hint="每个码最多可使用 10000 次。"
        />
        <Field
          label="标签"
          id="generate-wallet-label"
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
