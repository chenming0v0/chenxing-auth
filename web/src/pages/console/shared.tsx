import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import {
  apiFetch, getEntitlements,
  type AuthorizedOAuthApp, type EntitlementItem, type EntitlementsResponse,
  type OwnedOAuthClient, type OwnedOAuthClientList, type SessionItem,
} from '../../api'
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
  const requestId = useRef(0)
  // 返回 Promise 而不是 void：调用方在同一个「重试」动作里串联多个 loader 时
  // 需要知道这一次请求何时结束，否则无法保证重试顺序。
  const load = useCallback((force = false) => {
    const id = ++requestId.current
    setLoading(true)
    setError('')
    return getEntitlements(force)
      .then((value) => {
        if (id !== requestId.current) return
        setData(value)
      })
      .catch((reason: unknown) => {
        if (id !== requestId.current) return
        setError(reason instanceof Error ? reason.message : '权益数据加载失败。')
      })
      .finally(() => {
        if (id === requestId.current) setLoading(false)
      })
  }, [])
  useEffect(() => {
    void load()
    return () => { requestId.current += 1 }
  }, [load])
  return { data, error, loading, retry: useCallback(() => load(true), [load]) }
}

/**
 * 读取当前用户的全部 OAuth Client。接口按 limit/offset 分页，调用方不需要
 * 关心 200 条上限或手动拼接页；响应缺少 total 时仍按短页兼容旧后端。
 */
export async function listAllOwnedOAuthClients(): Promise<OwnedOAuthClient[]> {
  const limit = 200
  const clients: OwnedOAuthClient[] = []
  let offset = 0

  const seenPageFingerprints = new Set<string>()

  while (true) {
    const path = offset === 0
      ? '/api/v1/auth/oauth-clients'
      : `/api/v1/auth/oauth-clients?limit=${limit}&offset=${offset}`
    const response = await apiFetch<OwnedOAuthClientList>(path)
    const fingerprint = response.items.map((client) => client.client_id).join('|')
    if (response.items.length === limit && seenPageFingerprints.has(fingerprint)) break
    seenPageFingerprints.add(fingerprint)
    clients.push(...response.items)
    offset += response.items.length
    const total = response.total
    if (response.items.length < limit || (typeof total === 'number' && offset >= total)) break
  }

  return clients
}

export type AccountSummary = {
  clients: OwnedOAuthClient[]
  sessions: SessionItem[]
  apps: AuthorizedOAuthApp[]
}

const EMPTY_SUMMARY: AccountSummary = { clients: [], sessions: [], apps: [] }

/**
 * 账户摘要（自有应用 / 会话 / 已授权应用）的可重复调用 loader。
 *
 * 必须是可重复调用的：三个接口任意一个失败时，页面上的「重试」要能真正重新请求它们，
 * 而不是只重跑权益接口。requestId 保证并发重试里只有最后一次的结果落到 state。
 */
export function useAccountSummary() {
  const [data, setData] = useState<AccountSummary>(EMPTY_SUMMARY)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const requestId = useRef(0)

  const load = useCallback(() => {
    const id = ++requestId.current
    setLoading(true)
    setError('')
    return Promise.all([
      listAllOwnedOAuthClients(),
      apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions'),
      apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps'),
    ]).then(([clientResponse, sessionResponse, appResponse]) => {
      if (id !== requestId.current) return
      setData({ clients: clientResponse, sessions: sessionResponse.items, apps: appResponse.items })
      setError('')
    }).catch((reason: unknown) => {
      if (id !== requestId.current) return
      setError(reason instanceof Error ? reason.message : '账户摘要加载失败。')
    }).finally(() => {
      if (id === requestId.current) setLoading(false)
    })
  }, [])

  useEffect(() => {
    void load()
    // 卸载后让 in-flight 响应失效，避免对已卸载组件 setState
    return () => { requestId.current += 1 }
  }, [load])

  return { data, error, loading, retry: load }
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
