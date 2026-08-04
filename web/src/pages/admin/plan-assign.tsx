import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AssignPlanInput } from '../../api'
import { Button, Notice, SelectField } from '../../components/ui'

let planCache: AdminPlan[] | null = null

/** 用户行内展开的套餐分配表单；分配走 POST /admin/users/{id}/plan。 */
export function AssignPlanForm({ userId, userName, onAssigned, onClose }: {
  userId: number
  userName: string
  onAssigned: () => void
  onClose: () => void
}) {
  const [plans, setPlans] = useState<AdminPlan[] | null>(planCache)
  const [planId, setPlanId] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  const [done, setDone] = useState(false)

  useEffect(() => {
    if (planCache) return
    let active = true
    void apiFetch<AdminPlan[]>('/api/v1/admin/plans')
      .then((value) => { planCache = value; if (active) setPlans(value) })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '套餐列表加载失败。') })
    return () => { active = false }
  }, [])

  const activePlans = plans?.filter((plan) => plan.status === 'active') ?? []

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!planId) { setError('请选择要分配的套餐。'); return }
    setError('')
    setSaving(true)
    try {
      const input: AssignPlanInput = {
        plan_id: Number(planId),
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
      }
      await apiFetch<void>(`/api/v1/admin/users/${userId}/plan`, { method: 'POST', body: JSON.stringify(input) })
      planCache = null
      setDone(true)
      onAssigned()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '套餐分配失败。')
    } finally {
      setSaving(false)
    }
  }

  return (
    <form onSubmit={(event) => void submit(event)} className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] p-4">
      <p className="chenxing-body text-sm font-semibold">为 {userName} 分配套餐</p>
      <p className="chenxing-caption mt-1">到期后自动回退默认套餐；留空到期时间表示永久有效。</p>
      {error ? <div className="mt-3"><Notice tone="warning">{error}</Notice></div> : null}
      {done ? <div className="mt-3"><Notice tone="success">套餐已分配。</Notice></div> : null}
      <div className="mt-4 grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
        <SelectField label="目标套餐" icon="crown" value={planId} onChange={(event) => setPlanId(event.target.value)}>
          <option value="">{plans ? '选择套餐' : '正在加载套餐…'}</option>
          {activePlans.map((plan) => (
            <option key={plan.id} value={plan.id}>{plan.name} · {plan.code}{plan.is_default ? '（默认）' : ''}</option>
          ))}
        </SelectField>
        <label className="block">
          <span className="chenxing-label">到期时间（可选）</span>
          <input className="chenxing-field" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
          <small className="chenxing-caption mt-1.5 block">留空表示永久有效</small>
        </label>
        <div className="flex items-end justify-end gap-3 pb-1">
          <Button variant="ghost" icon="x" onClick={onClose} disabled={saving}>关闭</Button>
          <Button icon="crown" type="submit" disabled={saving || !plans}>{saving ? '分配中…' : '分配套餐'}</Button>
        </div>
      </div>
    </form>
  )
}
