export function splitValues(value: string): string[] {
  return value.split(/[\n, ]+/).map((item) => item.trim()).filter(Boolean)
}

type QuotaLike = { quota: { daily_used: number; daily_limit: number | null; monthly_used: number; monthly_limit: number | null } }

/** 上限为 null 表示服务端没有给出该维度的数值上限（无套餐或无限额度），用 ∞ 表示，不渲染 undefined。 */
export function formatQuota(client: QuotaLike): string {
  const daily = client.quota.daily_limit ?? '∞'
  const monthly = client.quota.monthly_limit ?? '∞'
  return `今日 ${client.quota.daily_used}/${daily} · 本月 ${client.quota.monthly_used}/${monthly}`
}
