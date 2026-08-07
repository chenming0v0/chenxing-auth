import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type SecurityLimitsSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice } from '../../../components/ui'

type FieldKey = keyof SecurityLimitsSetting
type FieldSpec = { key: FieldKey; label: string; hint: string; maximum: bigint }
type FieldGroup = { title: string; description: string; fields: FieldSpec[] }

/** 与后端 SecurityLimitsSetting 的整数类型保持一致；QPS 另有更严格的业务上限。 */
const MAX_SOURCE_QPS = 1_000n
const MAX_U64 = 18_446_744_073_709_551_615n
const MAX_I64 = 9_223_372_036_854_775_807n

/** 13 个阈值按语义分三组；用描述表驱动渲染，避免同样的输入框写十三遍。 */
const GROUPS: FieldGroup[] = [
  {
    title: '源 IP 与账户限流',
    description: '决定暴力破解和洪泛的失败计数窗口与上限。',
    fields: [
      { key: 'unauthenticated_source_qps', label: '未认证来源 QPS 上限', hint: '默认 30，单位：次/秒', maximum: MAX_SOURCE_QPS },
      { key: 'ip_failure_limit', label: '单 IP 失败次数上限', hint: '默认 30，单位：次/窗口', maximum: MAX_I64 },
      { key: 'account_failure_limit', label: '单账户失败次数上限', hint: '默认 10，单位：次/窗口', maximum: MAX_I64 },
      { key: 'auth_failure_window_seconds', label: '认证失败计数窗口', hint: '默认 900，单位：秒', maximum: MAX_I64 },
      { key: 'totp_ticket_failure_limit', label: 'TOTP ticket 失败次数上限', hint: '默认 5，单位：次/ticket', maximum: MAX_I64 },
    ],
  },
  {
    title: '待决请求容量与 TTL',
    description: '限制授权确认页停留时长和未兑换凭据的堆积规模。',
    fields: [
      { key: 'max_pending_requests_per_client', label: '单 Client 待决请求上限', hint: '默认 20，单位：个', maximum: MAX_U64 },
      { key: 'max_pending_requests_global', label: '全局待决请求上限', hint: '默认 1000，单位：个', maximum: MAX_U64 },
      { key: 'pending_request_ttl_seconds', label: '待决授权请求 TTL', hint: '默认 600，单位：秒', maximum: MAX_U64 },
      { key: 'authorization_code_ttl_seconds', label: '授权码 TTL', hint: '默认 300，单位：秒；RFC 6749 建议不超过 600', maximum: MAX_U64 },
    ],
  },
  {
    title: '外部登录 state',
    description: '控制外部身份源回跳凭据的有效期和创建速率。',
    fields: [
      { key: 'external_login_state_ttl_seconds', label: 'State 有效期', hint: '默认 600，单位：秒', maximum: MAX_U64 },
      { key: 'external_login_state_rate_window_seconds', label: 'State 限流窗口', hint: '默认 60，单位：秒', maximum: MAX_U64 },
      { key: 'external_login_state_rate_limit', label: '单窗口单 IP 创建上限', hint: '默认 30，单位：个/窗口', maximum: MAX_I64 },
      { key: 'external_login_state_max_pending', label: '全局待决 state 上限', hint: '默认 10000，单位：个', maximum: MAX_I64 },
    ],
  },
]

const FIELD_KEYS: FieldSpec[] = GROUPS.flatMap((group) => group.fields)

/** 草稿态一律用字符串，保留用户正在输入的中间状态（含空串）。 */
function toDraft(value: SecurityLimitsSetting): Record<string, string> {
  return Object.fromEntries(FIELD_KEYS.map(({ key }) => [key, String(value[key])]))
}

export type SecurityLimitValidation = { value: string } | { error: string }

export function validateSecurityLimitInput(
  rawValue: string,
  label: string,
  maximum: bigint,
): SecurityLimitValidation {
  const raw = rawValue.trim()
  const positiveIntegerMessage = `「${label}」必须填写大于 0 的整数。`
  if (!raw) return { error: positiveIntegerMessage }

  const numeric = Number(raw)
  if (Number.isNaN(numeric)) {
    return { error: `「${label}」不是有效数字（NaN），请填写大于 0 的整数。` }
  }
  if (!Number.isFinite(numeric)) {
    return { error: `「${label}」必须是有限数字，不能为 Infinity。` }
  }
  if (!/^-?\d+$/.test(raw) || !Number.isInteger(numeric)) {
    return { error: positiveIntegerMessage }
  }

  const integer = BigInt(raw)
  if (integer <= 0n) return { error: positiveIntegerMessage }
  if (integer > maximum) {
    return { error: `「${label}」超出范围，必须在 1 到 ${maximum.toString()} 之间。` }
  }
  return { value: integer.toString() }
}

/** 保留后端 u64/i64 可接受的精确十进制 token，避免先转 JS number 后丢失低位。 */
function serializeSecurityLimits(payload: Record<string, string>): string {
  return `{${FIELD_KEYS.map(({ key }) => `${JSON.stringify(key)}:${payload[key]}`).join(',')}}`
}

export function SecurityLimitsPanel({ onMessage }: { onMessage: (message: string, tone?: 'success' | 'warning') => void }) {
  const [draft, setDraft] = useState<Record<string, string> | null>(null)
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    void apiFetch<SecurityLimitsSetting>('/api/v1/admin/settings/security-limits')
      .then((value) => { if (active) setDraft(toDraft(value)) })
      .catch((reason: unknown) => onMessage(reason instanceof Error ? reason.message : '安全限流配置加载失败。', 'warning'))
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [onMessage])

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!draft) return
    const payload: Record<string, string> = {}
    for (const { key, label, maximum } of FIELD_KEYS) {
      const result = validateSecurityLimitInput(draft[key] ?? '', label, maximum)
      if ('error' in result) {
        onMessage(result.error, 'warning')
        return
      }
      payload[key] = result.value
    }
    setBusy(true)
    try {
      const updated = await apiFetch<SecurityLimitsSetting>('/api/v1/admin/settings/security-limits', {
        method: 'PUT',
        body: serializeSecurityLimits(payload),
      })
      setDraft(toDraft(updated))
      onMessage('安全限流配置已保存，重启服务后生效。', 'warning')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : '安全限流配置保存失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <h2 className="chenxing-h2 flex items-center gap-2">
        <Icon name="shield" className="text-[var(--chenxing-cyan)]" size={18} />
        配置安全限流阈值
      </h2>
      <p className="chenxing-caption mt-1.5">用以在暴力破解或洪泛发生时调整边界；配置保存后需重启服务才能生效。</p>
      {loading || !draft ? (
        <div className="mt-5"><Notice>正在加载安全限流配置。</Notice></div>
      ) : (
        <form className="mt-5 flex flex-col gap-6" noValidate onSubmit={save}>
          {GROUPS.map((group) => (
            <div key={group.title}>
              <h3 className="chenxing-h3">{group.title}</h3>
              <p className="chenxing-caption mt-1 mb-3">{group.description}</p>
              <div className="grid gap-4 sm:grid-cols-2">
                {group.fields.map(({ key, label, hint, maximum }) => (
                  <Field
                    key={key}
                    label={label}
                    hint={hint}
                    type="number"
                    inputMode="numeric"
                    min="1"
                    max={maximum.toString()}
                    step="1"
                    value={draft[key]}
                    onChange={(event) => setDraft({ ...draft, [key]: event.target.value })}
                  />
                ))}
              </div>
            </div>
          ))}
          <div>
            <Button type="submit" icon="save" disabled={busy}>保存安全限流配置</Button>
          </div>
        </form>
      )}
    </HudPanel>
  )
}
