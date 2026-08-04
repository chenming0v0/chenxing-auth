import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AdminPlanInput } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Field, HudPanel, Icon, Notice, PageIntro, TextAreaField, ToggleRow } from '../../components/ui'
import { AdminGate, useAdminAccess } from './shared'

export function formatLimit(value: number | null): string {
  return value === null ? '∞' : value.toLocaleString('zh-CN')
}

export function AdminPlans() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Admin · Plans"
        title="套餐管理"
        description="定义辰星通行证的套餐矩阵：额度、并发与默认回退。套餐数量不设上限，额度留空即为无限。"
      />
      <AdminGate access={access} permission="manage_settings"><PlansManager /></AdminGate>
    </ConsoleLayout>
  )
}

type EditorState = { mode: 'create' } | { mode: 'edit'; plan: AdminPlan } | null

function PlansManager() {
  const [plans, setPlans] = useState<AdminPlan[] | null>(null)
  const [error, setError] = useState('')
  const [editor, setEditor] = useState<EditorState>(null)
  const [busyId, setBusyId] = useState<number | null>(null)

  const reload = useCallback(() => {
    void apiFetch<AdminPlan[]>('/api/v1/admin/plans')
      .then((value) => { setPlans(value); setError('') })
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : '套餐列表加载失败。'))
  }, [])
  useEffect(() => { reload() }, [reload])

  async function changeStatus(plan: AdminPlan) {
    const operation = plan.status === 'active' ? 'archive' : 'restore'
    if (operation === 'archive' && !window.confirm(`确认归档套餐「${plan.name}」吗？归档后不能再分配给用户，已挂载的 ${plan.assigned_users} 个用户将在到期或重新分配后回退默认套餐。`)) return
    setBusyId(plan.id)
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/plans/${plan.id}/${operation}`, { method: 'POST' })
      reload()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '套餐状态更新失败。')
    } finally {
      setBusyId(null)
    }
  }

  const activeCount = plans?.filter((plan) => plan.status === 'active').length ?? null
  const defaultPlan = plans?.find((plan) => plan.is_default) ?? null

  return (
    <>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="套餐总数" icon="layers" value={plans ? String(plans.length) : '—'} caption="含已归档套餐" />
        <StatCard label="启用中" icon="check" value={activeCount === null ? '—' : String(activeCount)} caption="可分配给用户" />
        <StatCard label="已归档" icon="box" value={plans ? String(plans.length - (activeCount ?? 0)) : '—'} caption="仅保留历史记录" />
        <StatCard label="默认套餐" icon="crown" value={defaultPlan?.code ?? '—'} caption={defaultPlan ? `${defaultPlan.name} · 未挂载用户的回退项` : '等待服务端数据'} mono />
      </div>

      {error ? <div className="mt-5"><Notice tone="warning">{error}</Notice></div> : null}

      <HudPanel className="mt-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="chenxing-h2">套餐矩阵</h2>
            <p className="chenxing-caption mt-1">额度与并发限制实时生效于配额检查；默认套餐受服务端约束保护，不能归档或取消默认。</p>
          </div>
          <Button icon="plus" onClick={() => setEditor({ mode: 'create' })}>新建套餐</Button>
        </div>

        <div className="mt-5 overflow-x-auto rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)]">
          <table className="w-full min-w-[1080px] text-left">
            <thead>
              <tr className="border-b border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.5)]">
                <th className="chenxing-label px-4 py-3">套餐</th>
                <th className="chenxing-label px-4 py-3">OAuth 应用</th>
                <th className="chenxing-label px-4 py-3">每日授权</th>
                <th className="chenxing-label px-4 py-3">每月授权</th>
                <th className="chenxing-label px-4 py-3">QPS</th>
                <th className="chenxing-label px-4 py-3">挂载用户</th>
                <th className="chenxing-label px-4 py-3">状态</th>
                <th className="chenxing-label px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {plans?.map((plan) => {
                const archived = plan.status !== 'active'
                return (
                  <tr key={plan.id} className={`border-t border-[var(--chenxing-border)]${archived ? ' opacity-60' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <p className="chenxing-body text-sm font-semibold">{plan.name}</p>
                        {plan.is_default ? <Badge tone="success"><Icon name="crown" size={12} />默认</Badge> : null}
                      </div>
                      <p className="chenxing-mono mt-0.5 text-xs text-[var(--chenxing-cyan)]">{plan.code}</p>
                      {plan.description ? <p className="chenxing-caption mt-0.5 max-w-xs truncate text-xs" title={plan.description}>{plan.description}</p> : null}
                    </td>
                    <td className="chenxing-mono px-4 py-3 text-sm">{formatLimit(plan.oauth_clients_limit)}</td>
                    <td className="chenxing-mono px-4 py-3 text-sm">{formatLimit(plan.daily_auth_limit)}</td>
                    <td className="chenxing-mono px-4 py-3 text-sm">{formatLimit(plan.monthly_auth_limit)}</td>
                    <td className="chenxing-mono px-4 py-3 text-sm">{formatLimit(plan.max_qps)}</td>
                    <td className="chenxing-mono px-4 py-3 text-sm">{plan.assigned_users.toLocaleString('zh-CN')}</td>
                    <td className="px-4 py-3">
                      <Badge tone={archived ? 'warning' : 'success'}>
                        <Icon name={archived ? 'circle-alert' : 'check'} size={12} />
                        {archived ? '已归档' : '启用中'}
                      </Badge>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="inline-flex items-center gap-3">
                        <button type="button" className="chenxing-link" disabled={busyId === plan.id} onClick={() => setEditor({ mode: 'edit', plan })}>编辑</button>
                        <button
                          type="button"
                          className={`chenxing-link${archived ? '' : ' text-[var(--chenxing-error)]'}`}
                          disabled={busyId === plan.id || (plan.is_default && !archived)}
                          title={plan.is_default && !archived ? '默认套餐受保护，不能归档' : undefined}
                          onClick={() => void changeStatus(plan)}
                        >
                          {archived ? '恢复' : '归档'}
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
              {plans && !plans.length ? (
                <tr><td colSpan={8} className="px-4 py-10 text-center"><span className="chenxing-caption">还没有套餐，从「新建套餐」开始。</span></td></tr>
              ) : null}
              {!plans && !error ? (
                <tr><td colSpan={8} className="px-4 py-10 text-center"><span className="chenxing-caption">正在加载套餐列表。</span></td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </HudPanel>

      {editor ? (
        <PlanEditorDrawer
          key={editor.mode === 'edit' ? editor.plan.id : 'create'}
          initial={editor.mode === 'edit' ? editor.plan : null}
          onSaved={() => { setEditor(null); reload() }}
          onCancel={() => setEditor(null)}
        />
      ) : null}
    </>
  )
}

function StatCard({ label, icon, value, caption, mono = false }: { label: string; icon: string; value: string; caption: string; mono?: boolean }) {
  return (
    <HudPanel>
      <div className="flex items-center justify-between"><span className="chenxing-caption">{label}</span><Icon name={icon} className="text-[var(--chenxing-cyan)]" size={16} /></div>
      <p className={`${mono ? 'chenxing-mono' : 'chenxing-display'} mt-3 truncate text-3xl font-bold`}>{value}</p>
      <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">{caption}</p>
    </HudPanel>
  )
}

const CODE_PATTERN = /^[a-z0-9_-]{1,64}$/

/** 与「接入应用」注册抽屉同构的右侧编辑抽屉。 */
function PlanEditorDrawer({ initial, onSaved, onCancel }: { initial: AdminPlan | null; onSaved: () => void; onCancel: () => void }) {
  const [code, setCode] = useState(initial?.code ?? '')
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [oauthClients, setOauthClients] = useState(initial ? String(initial.oauth_clients_limit) : '2')
  const [dailyAuth, setDailyAuth] = useState(initial ? String(initial.daily_auth_limit) : '2500')
  const [monthlyAuth, setMonthlyAuth] = useState(initial?.monthly_auth_limit === null || !initial ? (initial ? '' : '50000') : String(initial.monthly_auth_limit))
  const [maxQps, setMaxQps] = useState(initial?.max_qps == null ? '' : String(initial.max_qps))
  const [isDefault, setIsDefault] = useState(initial?.is_default ?? false)
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)
  // 服务端约束：active 的默认套餐不能取消默认；只能通过把另一个套餐设为默认来接替。
  const defaultLocked = Boolean(initial?.is_default && initial.status === 'active')

  function parseRequired(raw: string, label: string, minimum: number): number {
    const value = Number(raw.trim())
    if (!raw.trim() || !Number.isInteger(value) || value < minimum) throw new Error(`${label}必须是不小于 ${minimum} 的整数。`)
    return value
  }
  function parseOptional(raw: string, label: string, minimum: number): number | null {
    if (!raw.trim()) return null
    return parseRequired(raw, label, minimum)
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    const normalizedCode = code.trim().toLowerCase()
    setError('')
    let input: AdminPlanInput
    try {
      if (!CODE_PATTERN.test(normalizedCode)) throw new Error('套餐代码需为 1-64 位小写字母、数字、下划线或连字符。')
      if (!name.trim()) throw new Error('套餐名称不能为空。')
      input = {
        code: normalizedCode,
        name: name.trim(),
        description: description.trim() || null,
        oauth_clients_limit: parseRequired(oauthClients, 'OAuth 应用数上限', 0),
        daily_auth_limit: parseRequired(dailyAuth, '每日授权上限', 0),
        monthly_auth_limit: parseOptional(monthlyAuth, '每月授权上限', 0),
        max_qps: parseOptional(maxQps, 'QPS 上限', 1),
        is_default: isDefault,
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '表单校验失败。')
      return
    }
    setSaving(true)
    try {
      await apiFetch<AdminPlan>(initial ? `/api/v1/admin/plans/${initial.id}` : '/api/v1/admin/plans', {
        method: initial ? 'PUT' : 'POST',
        body: JSON.stringify(input),
      })
      onSaved()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '套餐保存失败。')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="chenxing-drawer-overlay is-open" onClick={onCancel}>
      <div className="chenxing-drawer is-open" onClick={(event) => event.stopPropagation()}>
        <div className="chenxing-drawer-header">
          <div>
            <h2 className="chenxing-h2">{initial ? '编辑套餐' : '新建套餐'}</h2>
            <p className="chenxing-caption mt-1">额度字段留空表示无限制；保存后立即作用于配额检查。</p>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onCancel}><Icon name="x" size={16} /></button>
        </div>
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={(event) => void submit(event)}>
          <div className="chenxing-drawer-body space-y-4">
            {error ? <Notice tone="warning">{error}</Notice> : null}
          <div className="chenxing-hud-panel space-y-4 !p-5">
            <Field label="套餐代码" icon="terminal" value={code} onChange={(event) => setCode(event.target.value)} placeholder="例如 pro-max" hint="1-64 位小写字母、数字、_ 或 -，作为套餐唯一标识" required />
            <Field label="套餐名称" icon="crown" value={name} onChange={(event) => setName(event.target.value)} placeholder="例如 专业版" required />
            <TextAreaField label="套餐描述（可选）" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="展示给用户的一句话说明，最多 512 字。" />
          </div>
          <div className="chenxing-hud-panel space-y-4 !p-5">
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="OAuth 应用数上限" type="number" min={0} step={1} value={oauthClients} onChange={(event) => setOauthClients(event.target.value)} required />
              <Field label="每日授权调用上限" type="number" min={0} step={1} value={dailyAuth} onChange={(event) => setDailyAuth(event.target.value)} required />
              <Field label="每月授权调用上限" type="number" min={0} step={1} value={monthlyAuth} onChange={(event) => setMonthlyAuth(event.target.value)} placeholder="∞" hint="留空表示无限" />
              <Field label="QPS 上限" type="number" min={1} step={1} value={maxQps} onChange={(event) => setMaxQps(event.target.value)} placeholder="∞" hint="留空表示不限并发" />
            </div>
            <ToggleRow
              title="设为默认套餐"
              description={defaultLocked ? '当前默认套餐受保护；要更换默认，请把另一个套餐设为默认来接替。' : '未挂载或套餐到期的用户将回退到默认套餐。设定后会替换现有默认。'}
              checked={isDefault}
              onChange={setIsDefault}
              disabled={defaultLocked}
            />
          </div>
          </div>
          <div className="chenxing-drawer-footer">
            <Button type="button" variant="ghost" onClick={onCancel}>取消</Button>
            <Button type="submit" icon="save" disabled={saving}>{saving ? '保存中…' : initial ? '保存更新' : '创建套餐'}</Button>
          </div>
        </form>
      </div>
    </div>
  )
}
