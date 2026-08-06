import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AssignPlanInput } from '../../api'
import { Button, Field, HudPanel, Notice } from '../../components/ui'
import { Drawer } from '../../components/drawer'
import { SelectField } from '../../components/select'

let planCache: AdminPlan[] | null = null

/** 复用共享 Drawer 的套餐分配抽屉；分配走 POST /admin/users/{id}/plan。 */
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
      // 分配会改变套餐的占用情况，缓存作废，下次打开重新拉取。
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
    <Drawer
      title={`为 ${userName} 分配套餐`}
      description="到期后自动回退默认套餐；留空到期时间表示永久有效。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>取消</Button>
          <Button type="submit" icon="crown" disabled={saving || !plans}>{saving ? '分配中…' : '分配套餐'}</Button>
        </>
      }
    >
      {error ? <Notice tone="warning">{error}</Notice> : null}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">套餐与有效期</p>
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
          hint="只列出启用中的套餐，已归档套餐不能分配。"
        />
        <Field
          label="到期时间（选填）"
          icon="calendar-clock"
          type="datetime-local"
          value={expiresAt}
          onChange={(event) => setExpiresAt(event.target.value)}
          hint="留空表示永久有效，到期后自动回退默认套餐。"
        />
      </HudPanel>
    </Drawer>
  )
}
