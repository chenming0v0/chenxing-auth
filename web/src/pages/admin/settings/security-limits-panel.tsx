import { useState, type FormEvent } from 'react'
import { apiFetch, type SecurityLimitsSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice } from '../../../components/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, type SettingsPanelProps } from './panel'

type FieldKey = keyof SecurityLimitsSetting
type FieldSpec = { key: FieldKey; label: string; hint: string; maximum: number }
type FieldGroup = { title: string; description: string; fields: FieldSpec[] }

/** JSON 请求使用 JavaScript number，因此边界必须停在可精确表示的安全整数。 */
const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER

/**
 * 每项的上界必须与后端 `config_limit_bounds.rs` 的 `MAX_*` 常量一致（#260）。
 * 阈值本身就是安全控制，填极值等于静默关掉这项控制，因此后端对越界值一律返回
 * 400；这里同步上界只是为了让管理员在提交前就看到范围，而不是把校验搬到前端。
 */
const MAX_UNAUTHENTICATED_SOURCE_QPS = 1_000
const MAX_AUTHORIZATION_CODE_TTL_SECONDS = 600
const MAX_PENDING_REQUEST_TTL_SECONDS = 3_600
const MAX_PENDING_REQUESTS_PER_CLIENT = 10_000
const MAX_PENDING_REQUESTS_GLOBAL = 1_000_000
const MAX_AUTH_FAILURE_WINDOW_SECONDS = 86_400
const MAX_ACCOUNT_FAILURE_LIMIT = 1_000
const MAX_IP_FAILURE_LIMIT = 10_000
const MAX_TOTP_TICKET_FAILURE_LIMIT = 100
const MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS = 3_600
const MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS = 3_600
const MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT = 10_000
const MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING = 1_000_000

/** 13 个阈值按语义分三组；用描述表驱动渲染，避免同样的输入框写十三遍。 */
const GROUPS: FieldGroup[] = [
  {
    title: '源 IP 与账户限流',
    description: '决定暴力破解和洪泛的失败计数窗口与上限。',
    fields: [
      { key: 'unauthenticated_source_qps', label: '未认证来源 QPS 上限', hint: '默认 30，上限 1000，单位：次/秒', maximum: MAX_UNAUTHENTICATED_SOURCE_QPS },
      { key: 'ip_failure_limit', label: '单 IP 失败次数上限', hint: '默认 30，上限 10000，单位：次/窗口', maximum: MAX_IP_FAILURE_LIMIT },
      { key: 'account_failure_limit', label: '单账户失败次数上限', hint: '默认 10，上限 1000，单位：次/窗口', maximum: MAX_ACCOUNT_FAILURE_LIMIT },
      { key: 'auth_failure_window_seconds', label: '认证失败计数窗口', hint: '默认 900，上限 86400，单位：秒', maximum: MAX_AUTH_FAILURE_WINDOW_SECONDS },
      { key: 'totp_ticket_failure_limit', label: 'TOTP ticket 失败次数上限', hint: '默认 5，上限 100，单位：次/ticket', maximum: MAX_TOTP_TICKET_FAILURE_LIMIT },
    ],
  },
  {
    title: '待决请求容量与 TTL',
    description: '限制授权确认页停留时长和未兑换凭据的堆积规模。',
    fields: [
      { key: 'max_pending_requests_per_client', label: '单 Client 待决请求上限', hint: '默认 20，上限 10000，单位：个', maximum: MAX_PENDING_REQUESTS_PER_CLIENT },
      { key: 'max_pending_requests_global', label: '全局待决请求上限', hint: '默认 1000，上限 1000000，单位：个', maximum: MAX_PENDING_REQUESTS_GLOBAL },
      { key: 'pending_request_ttl_seconds', label: '待决授权请求 TTL', hint: '默认 600，上限 3600，单位：秒', maximum: MAX_PENDING_REQUEST_TTL_SECONDS },
      { key: 'authorization_code_ttl_seconds', label: '授权码 TTL', hint: '默认 300，上限 600，单位：秒；上限取自 RFC 6749 §4.1.2', maximum: MAX_AUTHORIZATION_CODE_TTL_SECONDS },
    ],
  },
  {
    title: '外部登录 state',
    description: '控制外部身份源回跳凭据的有效期和创建速率。',
    fields: [
      { key: 'external_login_state_ttl_seconds', label: 'State 有效期', hint: '默认 600，上限 3600，单位：秒', maximum: MAX_EXTERNAL_LOGIN_STATE_TTL_SECONDS },
      { key: 'external_login_state_rate_window_seconds', label: 'State 限流窗口', hint: '默认 60，上限 3600，单位：秒', maximum: MAX_EXTERNAL_LOGIN_STATE_RATE_WINDOW_SECONDS },
      { key: 'external_login_state_rate_limit', label: '单窗口单 IP 创建上限', hint: '默认 30，上限 10000，单位：个/窗口', maximum: MAX_EXTERNAL_LOGIN_STATE_RATE_LIMIT },
      { key: 'external_login_state_max_pending', label: '全局待决 state 上限', hint: '默认 10000，上限 1000000，单位：个', maximum: MAX_EXTERNAL_LOGIN_STATE_MAX_PENDING },
    ],
  },
]

const FIELD_KEYS: FieldSpec[] = GROUPS.flatMap((group) => group.fields)

/** 草稿态一律用字符串，保留用户正在输入的中间状态（含空串）。 */
function toDraft(value: SecurityLimitsSetting): Record<string, string> {
  return Object.fromEntries(FIELD_KEYS.map(({ key }) => [key, String(value[key])]))
}

export type SecurityLimitValidation = { value: number } | { error: string }

export function validateSecurityLimitInput(
  rawValue: string,
  label: string,
  maximum: number,
): SecurityLimitValidation {
  const raw = rawValue.trim()
  const positiveIntegerMessage = `「${label}」必须填写大于 0 的整数。`
  if (!raw) return { error: positiveIntegerMessage }

  const numeric = Number(raw)
  if (Number.isNaN(numeric)) {
    return { error: `「${label}」不是有效数字（NaN），请填写大于 0 的整数。` }
  }
  if (!Number.isFinite(numeric)) {
    return { error: `「${label}」必须是有限数字，不能为 ${numeric}。` }
  }
  if (!Number.isInteger(numeric)) {
    return { error: positiveIntegerMessage }
  }
  if (numeric <= 0) return { error: positiveIntegerMessage }
  if (!Number.isSafeInteger(numeric)) {
    return { error: `「${label}」超出 JavaScript 安全整数范围，最大为 ${MAX_SAFE_INTEGER}。` }
  }
  if (numeric > maximum) {
    return { error: `「${label}」超出范围，必须在 1 到 ${maximum} 之间。` }
  }
  return { value: numeric }
}

export function SecurityLimitsPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [draft, setDraft] = useState<Record<string, string> | null>(null)
  /* 上次成功加载/保存的基线：当前草稿与它不一致即视为有未保存修改（#381）。 */
  const [savedDraft, setSavedDraft] = useState<Record<string, string> | null>(null)
  const [busy, setBusy] = useState(false)

  const { loading } = useSettingsResource<SecurityLimitsSetting>({
    path: '/api/v1/admin/settings/security-limits',
    onMessage,
    failureMessage: '安全限流配置加载失败。',
    apply: (value) => {
      const next = toDraft(value)
      setDraft(next)
      setSavedDraft(next)
    },
  })

  const dirty = Boolean(savedDraft && !settingsEqual(draft, savedDraft))
  useDirtyReport(dirty, onDirtyChange)

  function updateDraft(key: FieldKey, value: string) {
    if (busy) return
    setDraft((current) => current ? { ...current, [key]: value } : current)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !draft) return
    const payload: Record<string, number> = {}
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
        body: JSON.stringify(payload),
      })
      const next = toDraft(updated)
      setDraft(next)
      setSavedDraft(next)
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
          <fieldset disabled={busy} className="contents">
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
                      max={maximum}
                      step="1"
                      value={draft[key]}
                      onChange={(event) => updateDraft(key, event.target.value)}
                    />
                  ))}
                </div>
              </div>
            ))}
            <div>
              <Button type="submit" icon="save" disabled={busy}>保存安全限流配置</Button>
            </div>
          </fieldset>
        </form>
      )}
    </HudPanel>
  )
}
