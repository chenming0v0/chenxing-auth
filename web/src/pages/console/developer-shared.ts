export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `cx-${Date.now()}-${Math.random().toString(36).slice(2)}`
}

export const REDIRECT_URI_RULE_MESSAGE = '仅允许 HTTPS；本地 HTTP 回调必须使用 127.0.0.1 或 [::1]，不接受 localhost、通配符与危险协议。'

// 前端镜像后端 src/clients/domain.rs::validate_redirect_uri 的规则集；前端只做即时反馈，服务端仍是权威校验。
export function redirectUriProblem(value: string): string | null {
  if (value.includes('*')) return '不接受通配符'
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return '不是合法的 URL'
  }
  const { protocol, hostname, hash, username, password } = url
  if (protocol !== 'https:' && (protocol !== 'http:' || !isLoopbackHostname(hostname))) {
    return '仅允许 HTTPS，或 HTTP 回环地址（127.0.0.1 / [::1]）'
  }
  if (hash) return '不允许包含 fragment'
  if (username || password) return '不允许包含用户名或密码'
  return null
}

function isLoopbackHostname(hostname: string): boolean {
  // WHATWG URL 把 IPv6 host 序列化为带方括号形式，如 "[::1]"
  if (hostname === '[::1]') return true
  const octets = hostname.split('.')
  return octets.length === 4 && octets[0] === '127' && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
}

export function findInvalidRedirectUri(redirectUris: string[]): { value: string; reason: string } | null {
  for (const value of redirectUris) {
    const reason = redirectUriProblem(value)
    if (reason !== null) return { value, reason }
  }
  return null
}

/** Logo / 主页只接受公网 HTTPS，禁止上传、data URL 和回环地址。 */
export function httpsUriProblem(value: string): string | null {
  if (value.includes('*')) return '不接受通配符'
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return '不是合法的 URL'
  }
  if (url.protocol !== 'https:') return '仅允许 HTTPS'
  if (url.hash) return '不允许包含 fragment'
  if (url.username || url.password) return '不允许包含用户名或密码'
  return null
}

/**
 * The API uses a null daily limit to signal that no effective plan exists.
 * A null monthly limit is only unlimited when the daily limit is present.
 */
type QuotaLike = { quota: { daily_used: number; daily_limit: number | null; monthly_used: number; monthly_limit: number | null } }

export function formatQuota(client: QuotaLike): string {
  if (client.quota.daily_limit === null) return '今日 不可用 · 本月 不可用'
  const monthly = client.quota.monthly_limit ?? '∞'
  return `今日 ${client.quota.daily_used}/${client.quota.daily_limit} · 本月 ${client.quota.monthly_used}/${monthly}`
}
