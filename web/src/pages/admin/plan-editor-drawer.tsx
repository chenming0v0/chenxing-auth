import { useState, type FormEvent } from 'react'
import { apiFetch, type AdminPlan, type AdminPlanInput, type BillingPeriod } from '../../api'
import { Drawer } from '../../components/drawer'
import { Button, Field, HudPanel, Notice, TextAreaField, ToggleRow } from '../../components/ui'
import { SelectField } from '../../components/select'
import { useMutationLock } from '../../use-mutation-lock'

const CODE_PATTERN = /^[a-z0-9_-]{1,64}$/
/** 必须与 `src/plans/domain.rs` 的业务上界保持一致（Issue #415 / #459）。 */
const MAX_OAUTH_CLIENTS_LIMIT = 1000
const MAX_DAILY_AUTH_LIMIT = 1_000_000
const MAX_MONTHLY_AUTH_LIMIT = 31_000_000
const MAX_QPS = 10_000

const BILLING_OPTIONS: { value: BillingPeriod; label: string }[] = [
  { value: 'one_time', label: '一次性' },
  { value: 'monthly', label: '每月' },
  { value: 'yearly', label: '每年' },
]

function asBillingPeriod(value: string | undefined): BillingPeriod {
  return value === 'monthly' || value === 'yearly' || value === 'one_time' ? value : 'one_time'
}

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

/** 复用共享 Drawer 的右侧编辑抽屉，焦点管理与「接入应用」抽屉一致。 */
export function PlanEditorDrawer({ initial, defaultOn = false, onSaved, onCancel }: {
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
  const [pricePoints, setPricePoints] = useState(initial ? String(initial.price_points) : '0')
  const [billingPeriod, setBillingPeriod] = useState<BillingPeriod>(asBillingPeriod(initial?.billing_period))
  const [isDefault, setIsDefault] = useState(initial?.is_default ?? defaultOn)
  const [error, setError] = useState('')
  const { busy: saving, run } = useMutationLock()
  // 取消唯一默认套餐会让全站自助接入关闭，这是允许的操作，但必须提前说清后果。
  const clearingLastDefault = Boolean(initial?.is_default && initial.status === 'active' && !isDefault)

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
        price_points: parseRequired(pricePoints, '售价', 0, Number.MAX_SAFE_INTEGER),
        billing_period: billingPeriod,
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
      description="额度字段留空表示无限制；售价为 0 表示仅管理员分配。保存后立即作用于配额检查。"
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
          <Field label="售价（辰星点）" type="number" min={0} step={1} value={pricePoints} onChange={(event) => setPricePoints(event.target.value)} hint="0 表示仅管理员分配，用户不能自助购买" />
          <SelectField
            label="计费周期"
            icon="calendar-clock"
            value={billingPeriod}
            onChange={(value) => setBillingPeriod(asBillingPeriod(value))}
            options={BILLING_OPTIONS}
          />
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
