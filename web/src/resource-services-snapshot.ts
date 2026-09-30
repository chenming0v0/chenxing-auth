import type {
  ResourceServiceLoginFieldKey,
  ResourceServiceLoginStatus,
  ResourceServiceSnapshotField,
  ResourceServiceSubscription,
} from './resource-services-types'

export type SnapshotTone = 'neutral' | 'success' | 'warning'

export type StatusPresentation = { label: string; tone: SnapshotTone }

export type SubscriptionSummary = StatusPresentation & {
  /** 可展示的到期时间（RFC3339），永久 / 未订阅 / 未知时为 null。 */
  expiresAt: string | null
}

const DAY_MS = 86_400_000
/** 剩余不足一周时用 warning 提醒，让用户在到期前看到。 */
const SUBSCRIPTION_WARNING_DAYS = 7

const STATUS_LABELS: Record<string, StatusPresentation> = {
  active: { label: '正常', tone: 'success' },
  disabled: { label: '已禁用', tone: 'warning' },
  unknown: { label: '未知', tone: 'neutral' },
  bound: { label: '已绑定', tone: 'success' },
  unbound: { label: '未绑定', tone: 'neutral' },
}

/** 提供方状态值的中文展示；认不得的值原样输出，不猜语义。 */
export function statusPresentation(value: string | null): StatusPresentation {
  if (value === null || value === '') return { label: '已绑定', tone: 'success' }
  return STATUS_LABELS[value] ?? { label: value, tone: 'neutral' }
}

const CLTERMUX_LOGIN_FIELDS: { key: ResourceServiceLoginFieldKey; label: string }[] = [
  { key: 'chrome_termux_login', label: 'chrome-termux（浏览器版）登录状态' },
  { key: 'termux_chrome_login', label: 'termux-chrome（WebView 版）登录状态' },
]
const LOGIN_LABELS: Record<ResourceServiceLoginStatus, string> = {
  unbound: '未绑定',
  logged_out: '未登录',
  logged_in: '已登录',
  unknown: '未知',
}

export function cltermuxLoginStates(uid: string, fields: ResourceServiceSnapshotField[]) {
  // 绑定 UID 是协议身份，不依赖可编辑的提供方名称，也不以快照自述 UID 猜产品。
  if (!/^cltermux:[1-9]\d*$/.test(uid)) return []
  return CLTERMUX_LOGIN_FIELDS.map((product) => {
    const field = fields.find((item) => item.key === product.key)
    const value = field?.type === 'status' ? field.value : null
    const status: ResourceServiceLoginStatus = value === 'unbound' || value === 'logged_out' || value === 'logged_in'
      ? value : 'unknown'
    return { ...product, status, value: LOGIN_LABELS[status] }
  })
}

function summarizeUntil(endMs: number, now: Date): SubscriptionSummary {
  if (Number.isNaN(endMs)) return { label: '未知', tone: 'neutral', expiresAt: null }
  const days = Math.max(0, Math.ceil((endMs - now.getTime()) / DAY_MS))
  const expiresAt = new Date(endMs).toISOString()
  if (days === 0) return { label: '已到期', tone: 'warning', expiresAt }
  return { label: `剩余 ${days} 天`, tone: days <= SUBSCRIPTION_WARNING_DAYS ? 'warning' : 'success', expiresAt }
}

/** 剩余天数在渲染时按 now 计算，而不是相信提供方抓取时的 remaining_seconds。 */
export function subscriptionSummary(subscription: ResourceServiceSubscription, now: Date): SubscriptionSummary {
  switch (subscription.kind) {
    case 'expires_at':
      return summarizeUntil(Date.parse(subscription.expires_at), now)
    case 'remaining':
      return summarizeUntil(Date.parse(subscription.as_of) + subscription.remaining_seconds * 1000, now)
    case 'permanent':
      return { label: '永久', tone: 'success', expiresAt: null }
    case 'none':
      return { label: '未订阅', tone: 'neutral', expiresAt: null }
    case 'unknown':
      return { label: '未知', tone: 'neutral', expiresAt: null }
  }
}

export function formatDuration(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds))
  const days = Math.floor(total / 86_400)
  const hours = Math.floor((total % 86_400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  if (days >= 1) return `${days} 天 ${hours} 小时`
  if (hours >= 1) return `${hours} 小时`
  return `${minutes} 分钟`
}

/** 头部已经展示账号状态，列表里不再重复；uid 字段由提供方自带 label，正常渲染。 */
const HEADER_FIELD_KEYS = new Set(['account_status'])
/** 订阅摘要已覆盖这几项，有摘要时不再逐条列出。 */
const SUBSCRIPTION_FIELD_KEYS = new Set(['is_subscribed', 'subscription_expires_at', 'remaining_seconds'])
/** CLtermux 的两版状态替代聚合设备状态；其他提供方仍按原协议展示。 */
const PRODUCT_FIELD_KEYS = new Set<string>(['device_status', ...CLTERMUX_LOGIN_FIELDS.map((field) => field.key)])

export function visibleSnapshotFields(
  fields: ResourceServiceSnapshotField[],
  hasSubscriptionSummary: boolean,
  hasProductLoginSummary = false,
): ResourceServiceSnapshotField[] {
  return fields.filter((field) =>
    !HEADER_FIELD_KEYS.has(field.key)
    && !(hasSubscriptionSummary && SUBSCRIPTION_FIELD_KEYS.has(field.key))
    && !(hasProductLoginSummary && PRODUCT_FIELD_KEYS.has(field.key)))
}
