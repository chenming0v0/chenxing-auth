import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AdminPlanInput } from '../../api'
import { Drawer } from '../../components/drawer'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Field, HudPanel, Icon, Notice, PageIntro, TextAreaField, ToggleRow } from '../../components/ui'
import { DataTable } from '../../components/data-table'
import { AdminGate, useAdminAccess } from './shared'
import { useMutationLock } from '../../use-mutation-lock'

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

type EditorState = { mode: 'create'; asDefault?: boolean } | { mode: 'edit'; plan: AdminPlan } | null

function PlansManager() {
  const [plans, setPlans] = useState<AdminPlan[] | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [editor, setEditor] = useState<EditorState>(null)
  // 行级 busy：多行操作可同时在途，先完成的行只清除自己的标记，不会像单值 busy 那样提前解禁其他行
  const [busyIds, setBusyIds] = useState<ReadonlySet<number>>(() => new Set())
  const reloadRequestId = useRef(0)

  const reload = useCallback(() => {
    const requestId = ++reloadRequestId.current
    setLoading(true)
    setError('')
    return apiFetch<AdminPlan[]>('/api/v1/admin/plans')
      .then((value) => {
        if (requestId !== reloadRequestId.current) return
        setPlans(value)
        setError('')
      })
      .catch((reason: unknown) => {
        if (requestId !== reloadRequestId.current) return
        setError(reason instanceof Error ? reason.message : '套餐列表加载失败。')
      })
      .finally(() => {
        if (requestId === reloadRequestId.current) setLoading(false)
      })
  }, [])
  useEffect(() => {
    void reload()
    return () => { reloadRequestId.current += 1 }
  }, [reload])

  async function changeStatus(plan: AdminPlan) {
    const operation = plan.status === 'active' ? 'archive' : 'restore'
    // 归档默认套餐会直接关闭全站自助接入，确认文案必须说明这个后果
    const defaultWarning = plan.is_default ? '这是当前的默认套餐，归档后全站自助接入将关闭，用户无法自行创建 OAuth 应用。' : ''
    if (operation === 'archive' && !window.confirm(`确认归档套餐「${plan.name}」吗？${defaultWarning}归档后不能再分配给用户，已挂载的 ${plan.assigned_users} 个用户会立即停止使用此套餐，并回退到当前启用的默认套餐；没有可用默认套餐时，自助接入会立即关闭。`)) return
    setBusyIds((prev) => new Set(prev).add(plan.id))
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/plans/${plan.id}/${operation}`, { method: 'POST' })
      await reload()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '套餐状态更新失败。')
    } finally {
      setBusyIds((prev) => { const next = new Set(prev); next.delete(plan.id); return next })
    }
  }

  const activeCount = plans?.filter((plan) => plan.status === 'active').length ?? null
  // 自助接入的开关就是「有没有一个 active 的默认套餐」：没有它，用户侧 plan 恒为 null
  const defaultPlan = plans?.find((plan) => plan.is_default && plan.status === 'active') ?? null
  const archivedDefault = plans?.find((plan) => plan.is_default && plan.status !== 'active') ?? null
  const selfServiceClosed = plans !== null && defaultPlan === null

  return (
    <>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="套餐总数" icon="layers" value={plans ? String(plans.length) : '—'} caption="含已归档套餐" />
        <StatCard label="启用中" icon="check" value={activeCount === null ? '—' : String(activeCount)} caption="可分配给用户" />
        <StatCard label="已归档" icon="box" value={plans ? String(plans.length - (activeCount ?? 0)) : '—'} caption="仅保留历史记录" />
        <StatCard
          label="默认套餐"
          icon={selfServiceClosed ? 'lock-keyhole' : 'crown'}
          value={defaultPlan ? defaultPlan.code : selfServiceClosed ? '未设置' : '—'}
          caption={defaultPlan
            ? `${defaultPlan.name} · 未挂载用户的回退项`
            : selfServiceClosed ? '全站自助接入已关闭' : '正在读取套餐列表'}
          mono={Boolean(defaultPlan)}
          tone={selfServiceClosed ? 'attention' : 'normal'}
        />
      </div>

      {error ? <div className="mt-5"><Notice tone="warning">{error}</Notice></div> : null}

      {selfServiceClosed ? (
        <HudPanel as="section" className="mt-5">
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="flex min-w-0 items-start gap-3">
              <span className="mt-0.5 inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[rgba(251,191,36,0.32)] bg-[rgba(251,191,36,0.08)] text-[var(--chenxing-warning)]">
                <Icon name="lock-keyhole" size={18} />
              </span>
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="chenxing-h2">全站自助接入已关闭</h2>
                  <Badge tone="warning"><Icon name="circle-alert" size={12} />无 active 默认套餐</Badge>
                </div>
                <p className="chenxing-caption mt-1.5">
                  {archivedDefault
                    ? `默认套餐「${archivedDefault.name}」已归档，系统当前没有启用中的默认套餐。`
                    : '系统当前没有设为默认的启用套餐。'}
                  未挂载套餐的用户在控制台看不到额度，也不能自助创建 OAuth 应用；接口会以 self_service_disabled 拒绝创建请求。
                </p>
                <p className="chenxing-caption mt-1.5">恢复方式：新建一个套餐并勾选「设为默认」，或把某个启用中的套餐设为默认，自助接入随即开放。</p>
              </div>
            </div>
            <Button icon="crown" onClick={() => setEditor({ mode: 'create', asDefault: true })}>新建默认套餐</Button>
          </div>
        </HudPanel>
      ) : null}

      <HudPanel className="mt-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="chenxing-h2">套餐矩阵</h2>
            <p className="chenxing-caption mt-1">额度与并发限制实时生效于配额检查；没有启用中的默认套餐时，全站自助接入处于关闭状态。</p>
          </div>
          <Button icon="plus" onClick={() => setEditor({ mode: 'create' })}>新建套餐</Button>
        </div>

        <DataTable
          minWidth={1080}
          columns={['套餐', 'OAuth 应用', '每日授权', '每月授权', 'QPS', '挂载用户', '状态', { label: '操作', align: 'right' }]}
          empty={plans?.length ? null : plans ? '还没有套餐，从「新建套餐」开始。' : error ? null : loading ? '正在加载套餐列表。' : null}
        >
          {plans?.map((plan) => {
            const archived = plan.status !== 'active'
            return (
              <tr key={plan.id} className={archived ? 'opacity-60' : ''}>
                <td>
                  <div className="flex items-center gap-2">
                    <p className="chenxing-body text-sm font-semibold">{plan.name}</p>
                    {plan.is_default ? <Badge tone="success"><Icon name="crown" size={12} />默认</Badge> : null}
                  </div>
                  <p className="chenxing-mono mt-0.5 text-xs text-[var(--chenxing-cyan)]">{plan.code}</p>
                  {plan.description ? <p className="chenxing-caption mt-0.5 max-w-xs truncate text-xs" title={plan.description}>{plan.description}</p> : null}
                </td>
                <td className="chenxing-mono text-sm">{formatLimit(plan.oauth_clients_limit)}</td>
                <td className="chenxing-mono text-sm">{formatLimit(plan.daily_auth_limit)}</td>
                <td className="chenxing-mono text-sm">{formatLimit(plan.monthly_auth_limit)}</td>
                <td className="chenxing-mono text-sm">{formatLimit(plan.max_qps)}</td>
                <td className="chenxing-mono text-sm">{plan.assigned_users.toLocaleString('zh-CN')}</td>
                <td>
                      <Badge tone={archived ? 'warning' : 'success'}>
                        <Icon name={archived ? 'circle-alert' : 'check'} size={12} />
                        {archived ? '已归档' : '启用中'}
                    </Badge>
                  </td>
                  <td className="text-right">
                      <div className="inline-flex items-center gap-3">
                        <button type="button" className="chenxing-link chenxing-row-action" disabled={busyIds.has(plan.id)} onClick={() => setEditor({ mode: 'edit', plan })}>编辑</button>
                        {/* 默认套餐不再受服务端保护：可以归档，也可以取消默认（代价是关闭自助接入） */}
                        <button
                          type="button"
                          className={`chenxing-link chenxing-row-action${archived ? '' : ' text-[var(--chenxing-error)]'}`}
                          disabled={busyIds.has(plan.id)}
                          onClick={() => void changeStatus(plan)}
                        >
                          {archived ? '恢复' : '归档'}
                        </button>
                      </div>
                    </td>
                </tr>
              )
            })}
          </DataTable>
      </HudPanel>

      {editor ? (
        <PlanEditorDrawer
          key={editor.mode === 'edit' ? editor.plan.id : 'create'}
          initial={editor.mode === 'edit' ? editor.plan : null}
          defaultOn={editor.mode === 'create' && Boolean(editor.asDefault)}
          onSaved={async () => { setEditor(null); await reload() }}
          onCancel={() => setEditor(null)}
        />
      ) : null}
    </>
  )
}

/** tone='attention' 表示这张卡承载一个需要管理员处理的状态；图标与文案同时表达，不只改颜色。 */
function StatCard({ label, icon, value, caption, mono = false, tone = 'normal' }: {
  label: string
  icon: string
  value: string
  caption: string
  mono?: boolean
  tone?: 'normal' | 'attention'
}) {
  const attention = tone === 'attention'
  return (
    <HudPanel>
      <div className="flex items-center justify-between">
        <span className="chenxing-caption">{label}</span>
        <Icon name={icon} className={attention ? 'text-[var(--chenxing-warning)]' : 'text-[var(--chenxing-cyan)]'} size={16} />
      </div>
      <p className={`${mono ? 'chenxing-mono' : 'chenxing-display'} mt-3 truncate ${attention ? 'text-2xl text-[var(--chenxing-warning)]' : 'text-3xl'} font-bold`}>{value}</p>
      <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">{caption}</p>
    </HudPanel>
  )
}

const CODE_PATTERN = /^[a-z0-9_-]{1,64}$/
/** 必须与 `src/plans/domain.rs` 的业务上界保持一致（Issue #415 / #459）。 */
const MAX_OAUTH_CLIENTS_LIMIT = 1000
const MAX_DAILY_AUTH_LIMIT = 1_000_000
const MAX_MONTHLY_AUTH_LIMIT = 31_000_000
const MAX_QPS = 10_000

/** 复用共享 Drawer 的右侧编辑抽屉，焦点管理与「接入应用」抽屉一致。 */
function PlanEditorDrawer({ initial, defaultOn = false, onSaved, onCancel }: {
  initial: AdminPlan | null
  /** 从「新建默认套餐」入口进入时预勾选「设为默认」，一步恢复自助接入 */
  defaultOn?: boolean
  onSaved: () => void | Promise<void>
  onCancel: () => void
}) {
  const [code, setCode] = useState(initial?.code ?? '')
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [oauthClients, setOauthClients] = useState(initial ? String(initial.oauth_clients_limit) : '2')
  const [dailyAuth, setDailyAuth] = useState(initial ? String(initial.daily_auth_limit) : '2500')
  const [monthlyAuth, setMonthlyAuth] = useState(initial?.monthly_auth_limit === null || !initial ? (initial ? '' : '50000') : String(initial.monthly_auth_limit))
  const [maxQps, setMaxQps] = useState(initial?.max_qps == null ? '' : String(initial.max_qps))
  const [isDefault, setIsDefault] = useState(initial?.is_default ?? defaultOn)
  const [error, setError] = useState('')
  const { busy: saving, run } = useMutationLock()
  // 取消唯一默认套餐会让全站自助接入关闭，这是允许的操作，但必须提前说清后果。
  const clearingLastDefault = Boolean(initial?.is_default && initial.status === 'active' && !isDefault)

  function parseRequired(raw: string, label: string, minimum: number, maximum: number): number {
    const value = Number(raw.trim())
    if (!raw.trim() || !Number.isInteger(value) || value < minimum) throw new Error(`${label}必须是不小于 ${minimum} 的整数。`)
    if (!Number.isSafeInteger(value)) throw new Error(`${label}超出 JavaScript 安全整数范围，最大为 ${Number.MAX_SAFE_INTEGER}。`)
    if (value > maximum) throw new Error(`${label}超出范围，必须在 ${minimum} 到 ${maximum} 之间。`)
    return value
  }
  function parseOptional(raw: string, label: string, minimum: number, maximum: number): number | null {
    if (!raw.trim()) return null
    return parseRequired(raw, label, minimum, maximum)
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
        oauth_clients_limit: parseRequired(oauthClients, 'OAuth 应用数上限', 0, MAX_OAUTH_CLIENTS_LIMIT),
        daily_auth_limit: parseRequired(dailyAuth, '每日授权上限', 0, MAX_DAILY_AUTH_LIMIT),
        monthly_auth_limit: parseOptional(monthlyAuth, '每月授权上限', 0, MAX_MONTHLY_AUTH_LIMIT),
        max_qps: parseOptional(maxQps, 'QPS 上限', 1, MAX_QPS),
        is_default: isDefault,
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '表单校验失败。')
      return
    }
    await run(async () => {
      try {
        await apiFetch<AdminPlan>(initial ? `/api/v1/admin/plans/${initial.id}` : '/api/v1/admin/plans', {
          method: initial ? 'PUT' : 'POST',
          body: JSON.stringify(input),
        })
        await onSaved()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : '套餐保存失败。')
      }
    })
  }

  return (
    <Drawer
      title={initial ? '编辑套餐' : '新建套餐'}
      description="额度字段留空表示无限制；保存后立即作用于配额检查。"
      onClose={onCancel}
      onSubmit={(event) => void submit(event)}
      busy={saving}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onCancel} disabled={saving}>取消</Button>
          <Button type="submit" icon="save" disabled={saving}>{saving ? '保存中…' : initial ? '保存更新' : '创建套餐'}</Button>
        </>
      }
    >
      {error ? <Notice tone="warning">{error}</Notice> : null}
      <HudPanel className="space-y-4 !p-5">
        <Field label="套餐代码" icon="terminal" value={code} onChange={(event) => setCode(event.target.value)} placeholder="例如 pro-max" hint="1-64 位小写字母、数字、_ 或 -，作为套餐唯一标识" required />
        <Field label="套餐名称" icon="crown" value={name} onChange={(event) => setName(event.target.value)} placeholder="例如 专业版" required />
        <TextAreaField label="套餐描述（可选）" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="展示给用户的一句话说明，最多 512 字。" />
      </HudPanel>
      <HudPanel className="space-y-4 !p-5">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="OAuth 应用数上限" type="number" min={0} step={1} value={oauthClients} onChange={(event) => setOauthClients(event.target.value)} required />
          <Field label="每日授权调用上限" type="number" min={0} step={1} value={dailyAuth} onChange={(event) => setDailyAuth(event.target.value)} required />
          <Field label="每月授权调用上限" type="number" min={0} step={1} value={monthlyAuth} onChange={(event) => setMonthlyAuth(event.target.value)} placeholder="∞" hint="留空表示无限" />
          <Field label="QPS 上限" type="number" min={1} step={1} value={maxQps} onChange={(event) => setMaxQps(event.target.value)} placeholder="∞" hint="留空表示不限并发" />
        </div>
        <ToggleRow
          title="设为默认套餐"
          description={clearingLastDefault
            ? '取消后系统将没有启用中的默认套餐，全站自助接入会关闭；如需保留，请把另一个套餐设为默认。'
            : '未挂载或套餐到期的用户将回退到默认套餐。设定后会替换现有默认，并开放自助接入。'}
          checked={isDefault}
          onChange={setIsDefault}
        />
      </HudPanel>
    </Drawer>
  )
}
