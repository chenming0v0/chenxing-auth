import { useEffect, useState } from 'react'
import { getEntitlements, type EntitlementItem, type EntitlementsResponse } from '../../api'

export function entitlementView(item: EntitlementItem) {
  const numericLimit = typeof item.limit === 'number' ? item.limit : null
  const hasLimit = numericLimit !== null
  const unlimited = item.limit === null
  const remaining = item.remaining ?? (numericLimit !== null ? Math.max(numericLimit - item.used, 0) : null)
  const progress = numericLimit !== null && numericLimit > 0 ? Math.min(item.used / numericLimit, 1) * 100 : numericLimit !== null ? 100 : 0
  return { hasLimit, unlimited, remaining, progress }
}

export function useEntitlements() {
  const [data, setData] = useState<EntitlementsResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const load = (force = false) => {
    setLoading(true)
    setError('')
    void getEntitlements(force)
      .then(setData)
      .catch((reason: unknown) => setError(reason instanceof Error ? reason.message : '权益数据加载失败。'))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])
  return { data, error, loading, retry: () => load(true) }
}

export function Meter({ value }: { value: number }) {
  return <div className="chenxing-meter mt-3"><div className="chenxing-meter-fill" style={{ width: `${Math.max(0, Math.min(value, 100))}%` }} /></div>
}
