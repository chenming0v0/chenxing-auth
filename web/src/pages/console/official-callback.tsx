import { useEffect, useState } from 'react'
import { Button, CopyValue } from '@chenxing/ui'
import { useAuth } from '../../auth-state'
import { Link } from '../../router'

/**
 * 官方手机应用的回调落在本 Issuer 的固定路径上；后端只认数字 ID 与 Client 自身一致的那条
 * （src/oauth/authorization.rs numeric_app_callback_allowed）。完整 URL 以 Discovery 的
 * `issuer` 为准，不从当前页面 origin 推导，避免反代或开发端口把地址拼错。
 */
export function officialCallbackPath(numericAppId: number): string {
  return `/app/${numericAppId}/oauth/callback`
}

export function officialCallbackUrl(issuer: string | null, numericAppId: number): string | null {
  return issuer ? `${issuer}${officialCallbackPath(numericAppId)}` : null
}

export function issuerFromDiscovery(body: unknown): string | null {
  if (!body || typeof body !== 'object' || !('issuer' in body)) return null
  const issuer = body.issuer
  if (typeof issuer !== 'string') return null
  const trimmed = issuer.trim().replace(/\/+$/, '')
  if (!/^https:\/\//i.test(trimmed)) return null
  return trimmed
}

/** 从 OIDC Discovery 读取 Issuer；取不到时返回 null，调用方退化为只展示路径。 */
export function useIssuer(): string | null {
  const [issuer, setIssuer] = useState<string | null>(null)
  useEffect(() => {
    let active = true
    void fetch('/.well-known/openid-configuration')
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        if (active) setIssuer(issuerFromDiscovery(body))
      })
      .catch(() => {
        if (active) setIssuer(null)
      })
    return () => {
      active = false
    }
  }, [])
  return issuer
}

export function OfficialCallbackValue({ numericAppId, issuer }: { numericAppId: number; issuer: string | null }) {
  const callbackPath = officialCallbackPath(numericAppId)
  const officialCallback = officialCallbackUrl(issuer, numericAppId)
  return (
    <div className="space-y-3">
      <div className="min-w-0">
        <p className="chenxing-label">官方回调路径</p>
        <CopyValue value={callbackPath} ariaLabel="复制官方回调路径" />
      </div>
      {officialCallback ? (
        <div className="min-w-0">
          <p className="chenxing-label">官方完整回调 URL</p>
          <CopyValue value={officialCallback} ariaLabel="复制官方完整回调 URL" />
        </div>
      ) : (
        <p className="chenxing-caption">完整地址是配置中的 Issuer 加上这条路径。</p>
      )}
    </div>
  )
}

export function AppLinksHint() {
  const { user } = useAuth()
  return (
    <p className="chenxing-caption">
      加入回调后，还需要 Owner 在「管理 · 软件链接」登记 Android 包名和签名指纹，手机才会把回调交给 App。
      {user?.role === 'owner' ? (
        <>
          {' '}
          <Link to="/admin/app-links" className="chenxing-link">去软件链接</Link>
        </>
      ) : null}
    </p>
  )
}

export type OfficialCallbackState = 'absent' | 'present' | 'full'

/**
 * 公开客户端的「官方回调」区块：展示地址、一键加入回调列表。
 * `state` 由调用方按当前回调列表判定；加入动作也由调用方落地（表单或 PUT）。
 */
export function OfficialCallbackBlock({
  numericAppId,
  issuer,
  state,
  busy = false,
  onAdd,
}: {
  numericAppId: number
  issuer: string | null
  state: OfficialCallbackState
  busy?: boolean
  onAdd: (url: string) => void
}) {
  const url = officialCallbackUrl(issuer, numericAppId)
  const label = state === 'present' ? '已加入' : busy ? '加入中…' : '加入回调列表'
  const hint = state === 'full'
    ? '回调列表已满，先移除一条再加入。'
    : url === null
      ? '取不到 Issuer，无法生成完整地址。'
      : undefined
  return (
    <div className="space-y-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="chenxing-body text-sm font-semibold">官方回调（本 Issuer）</p>
          <p className="chenxing-caption mt-0.5">官方手机应用不用自己的域名，直接用这条固定回调。</p>
        </div>
        <Button
          type="button"
          variant="ghost"
          icon={state === 'present' ? 'check' : 'plus'}
          disabled={busy || state !== 'absent' || url === null}
          onClick={() => {
            if (url) onAdd(url)
          }}
        >
          {label}
        </Button>
      </div>
      <OfficialCallbackValue numericAppId={numericAppId} issuer={issuer} />
      {hint ? <p className="chenxing-caption">{hint}</p> : null}
      <AppLinksHint />
    </div>
  )
}
