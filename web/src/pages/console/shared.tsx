import { useEffect, useState, type ReactNode } from 'react'
import { getEntitlements, type EntitlementItem, type EntitlementsResponse } from '../../api'
import { Icon } from '../../components/ui'

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

/**
 * 权益接口的四种页面状态。`closed` 对应 plan === null：这不是故障，
 * 而是「平台未开放自助接入」这一合法状态，页面必须与 `failed` 区分渲染。
 */
export type EntitlementState =
  | { kind: 'loading' }
  | { kind: 'failed'; message: string }
  | { kind: 'closed' }
  | { kind: 'ready'; data: EntitlementsResponse; plan: NonNullable<EntitlementsResponse['plan']> }

export function entitlementState({ data, error, loading }: { data: EntitlementsResponse | null; error: string; loading: boolean }): EntitlementState {
  // 已有数据优先：重试失败时保留上一次成功的视图，而不是把页面退回错误态
  if (data) return data.plan ? { kind: 'ready', data, plan: data.plan } : { kind: 'closed' }
  if (loading) return { kind: 'loading' }
  return { kind: 'failed', message: error || '权益数据加载失败。' }
}

export const SELF_SERVICE_CLOSED_TITLE = '平台未开放自助接入'
export const SELF_SERVICE_CLOSED_BODY = '平台尚未配置可自助领取的套餐，你的账号当前没有可用额度，也不能自行创建新的 OAuth 应用。需要接入请联系管理员为你分配套餐。'
export const SELF_SERVICE_CLOSED_KEPT = '已创建的应用不受影响，仍可正常登录与授权。'

/**
 * 「平台未开放自助接入」说明块。不自带玻璃容器，由调用方放进 HudPanel，
 * 避免玻璃面板嵌套。状态同时由图标、标题文字和正文表达，不依赖颜色。
 */
export function SelfServiceClosedBlock({ children, compact = false }: { children?: ReactNode; compact?: boolean }) {
  return (
    <div className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border-strong)] bg-[rgba(4,8,16,0.45)] p-5">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border-strong)] bg-[var(--chenxing-muted)] text-[var(--chenxing-muted-foreground)]">
          <Icon name="lock-keyhole" size={17} />
        </span>
        <div className="min-w-0">
          <p className="chenxing-body text-sm font-semibold">{SELF_SERVICE_CLOSED_TITLE}</p>
          <p className="chenxing-caption mt-1.5">{SELF_SERVICE_CLOSED_BODY}</p>
          {compact ? null : <p className="chenxing-caption mt-1.5">{SELF_SERVICE_CLOSED_KEPT}</p>}
          {children ? <div className="mt-4 flex flex-wrap items-center gap-3">{children}</div> : null}
        </div>
      </div>
    </div>
  )
}

export function Meter({ value }: { value: number }) {
  return <div className="chenxing-meter mt-3"><div className="chenxing-meter-fill" style={{ width: `${Math.max(0, Math.min(value, 100))}%` }} /></div>
}
