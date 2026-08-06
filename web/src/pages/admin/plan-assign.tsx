import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AssignPlanInput } from '../../api'
import { Button, HudPanel, Icon, Notice } from '../../components/ui'
import { SelectField } from '../../components/select'

let planCache: AdminPlan[] | null = null

/** 与「注册新应用」同构的右侧抽屉；分配走 POST /admin/users/{id}/plan。 */
export function AssignPlanDrawer({ userId, userName, onAssigned, onClose }: {
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
      onAssigned()
      onClose()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '套餐分配失败。')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="chenxing-drawer-overlay is-open" onClick={onClose}>
      <div className="chenxing-drawer is-open" onClick={(event) => event.stopPropagation()}>
        <div className="chenxing-drawer-header">
          <div>
            <h2 className="chenxing-h2">为 {userName} 分配套餐</h2>
            <p className="chenxing-caption mt-1">到期后自动回退默认套餐；留空表示永久有效。</p>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onClose}>
            <Icon name="x" size={16} />
          </button>
        </div>
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={(event) => void submit(event)}>
          <div className="chenxing-drawer-body space-y-4">
            <HudPanel className="space-y-4 !p-5">
              {error ? <Notice tone="warning">{error}</Notice> : null}
              <SelectField
                label="目标套餐"
                icon="crown"
                value={planId}
                onChange={setPlanId}
                placeholder={plans ? '选择套餐' : '正在加载套餐…'}
                options={activePlans.map((plan) => ({
                  value: String(plan.id),
                  label: `${plan.name} · ${plan.code}${plan.is_default ? '（默认）' : ''}`,
                }))}
              />
              <label className="block">
                <span className="chenxing-label">到期时间（可选）</span>
                <input className="chenxing-field" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} />
                <small className="chenxing-caption mt-1.5 block">留空表示永久有效</small>
              </label>
            </HudPanel>
          </div>
          <div className="chenxing-drawer-footer">
            <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>
              取消
            </Button>
            <Button type="submit" icon="crown" disabled={saving || !plans}>
              {saving ? '分配中…' : '分配套餐'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
