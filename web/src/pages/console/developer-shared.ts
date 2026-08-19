export function splitValues(value: string): string[] {
  return value.split(/[\n, ]+/).map((item) => item.trim()).filter(Boolean)
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
