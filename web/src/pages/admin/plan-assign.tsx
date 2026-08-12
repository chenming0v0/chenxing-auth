import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AssignPlanInput } from '../../api'
import { Button, Field, HudPanel, Notice } from '../../components/ui'
import { Drawer } from '../../components/drawer'
import { SelectField } from '../../components/select'

/** 复用共享 Drawer 的套餐分配抽屉；分配走 POST /admin/users/{id}/plan。 */
export function AssignPlanDrawer({ userId, userName, onAssigned, onClose }: {
  userId: number
  userName: string
  onAssigned: () => void
  onClose: () => void
}) {
  const [plans, setPlans] = useState<AdminPlan[] | null>(null)
  const [planId, setPlanId] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  // 每次打开抽屉都重新拉取套餐列表，不设模块级缓存（#373）：
  // 套餐的新建/归档/恢复/编辑发生在套餐管理页，注销换账号也没有失效入口，
  // 任何缓存都要额外维护失效点；抽屉按需挂载，拉取一次的成本可忽略，
  // 卸载时 active 守卫会丢弃在途响应，不存在跨账号写回。
  useEffect(() => {
    let active = true
    void apiFetch<AdminPlan[]>('/api/v1/admin/plans')
      .then((value) => { if (active) setPlans(value) })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '套餐列表加载失败。') })
    return () => { active = false }
  }, [])

  const activePlans = plans?.filter((plan) => plan.status === 'active') ?? []
  /* 「正在加载」和「确实没有可分配套餐」是两件事：
     plans === null 才是未拿到列表；拿到空数组或全部归档时必须说清系统里没有可选项。 */
  const listState = plans === null ? (error ? 'failed' : 'loading') : activePlans.length ? 'ready' : 'empty'
  const selectPlaceholder = listState === 'ready' ? '选择套餐'
    : listState === 'loading' ? '正在加载套餐…'
    : listState === 'empty' ? '没有可分配的套餐'
    : '套餐列表不可用'
  const selectHint = listState === 'empty'
    ? '系统里没有启用中的套餐。请先到「套餐管理」新建一个套餐，其中设为默认的套餐同时决定全站自助接入是否开放。'
    : '只列出启用中的套餐，已归档套餐不能分配。'

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
      busy={saving}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>取消</Button>
          <Button type="submit" icon="crown" disabled={saving || listState !== 'ready'}>{saving ? '分配中…' : '分配套餐'}</Button>
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
          disabled={listState !== 'ready'}
          placeholder={selectPlaceholder}
          options={activePlans.map((plan) => ({
            value: String(plan.id),
            label: `${plan.name} · ${plan.code}${plan.is_default ? '（默认）' : ''}`,
          }))}
          hint={selectHint}
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
