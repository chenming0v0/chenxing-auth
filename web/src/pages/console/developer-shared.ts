export function splitValues(value: string): string[] {
  return value.split(/[\n, ]+/).map((item) => item.trim()).filter(Boolean)
}

export function formatQuota(client: { quota: { daily_used: number; daily_limit: number; monthly_used: number; monthly_limit: number | null } }): string {
  return `今日 ${client.quota.daily_used}/${client.quota.daily_limit} · 本月 ${client.quota.monthly_used}/${client.quota.monthly_limit ?? '∞'}`
}
