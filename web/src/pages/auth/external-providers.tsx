import { useEffect, useState } from 'react'
import { apiFetch, type PublicExternalProvider } from '../../api'
import { Button, Icon, Notice } from '../../components/ui'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; providers: PublicExternalProvider[] }
  | { kind: 'failed' }

/**
 * 外部身份源入口。列表来自后端公开接口，不再硬编码。入口使用原生 <a>：
 * /auth/external/{slug} 会下发 state Cookie 并 302 到上游授权页，属于整页
 * 导航而非 SPA 路由；用锚点同时保留新标签页打开等浏览器原生行为。
 */
export function ExternalProviders({ requestId }: { requestId: string | null }) {
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [reloadToken, setReloadToken] = useState(0)

  useEffect(() => {
    let cancelled = false
    setState({ kind: 'loading' })
    apiFetch<PublicExternalProvider[]>('/api/v1/auth/external-providers', { redirectOn401: false })
      .then((providers) => {
        if (cancelled) return
        setState({ kind: 'ready', providers: providers.filter(isRenderableProvider) })
      })
      .catch(() => {
        if (!cancelled) setState({ kind: 'failed' })
      })
    return () => { cancelled = true }
  }, [reloadToken])

  if (state.kind === 'loading') {
    return <p className="chenxing-caption py-6 text-center">正在加载外部身份源…</p>
  }

  if (state.kind === 'failed') {
    return (
      <div className="space-y-3">
        <Notice tone="warning">外部身份源加载失败，请检查网络后重试。</Notice>
        <Button type="button" variant="ghost" icon="refresh-cw" className="w-full" onClick={() => setReloadToken((value) => value + 1)}>
          重新加载
        </Button>
      </div>
    )
  }

  if (state.providers.length === 0) {
    return <Notice tone="info">管理员尚未启用任何外部身份源，请使用账号登录。</Notice>
  }

  return (
    <div className="grid gap-3">
      {state.providers.map((provider) => (
        <a
          key={provider.slug}
          href={externalLoginUrl(provider.slug, requestId)}
          className="cx-factor-option"
          data-testid={`external-provider-${provider.slug}`}
        >
          <Icon name="globe" size={20} className="mt-0.5 shrink-0 text-[var(--chenxing-cyan)]" />
          {/* 名称由管理员配置，作为文本节点渲染，不允许注入 HTML。 */}
          <span className="min-w-0 flex-1 truncate text-sm font-medium text-[var(--chenxing-foreground)]">{provider.name}</span>
          <Icon name="arrow-up-right" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-muted-foreground)]" />
        </a>
      ))}
    </div>
  )
}

/** 保留 OAuth 授权请求，登录完成后仍能回到原授权流程。 */
export function externalLoginUrl(slug: string, requestId: string | null): string {
  const base = `/auth/external/${encodeURIComponent(slug)}`
  return requestId ? `${base}?request_id=${encodeURIComponent(requestId)}` : base
}

function isRenderableProvider(provider: PublicExternalProvider): boolean {
  return typeof provider?.slug === 'string' && provider.slug.length > 0
    && typeof provider?.name === 'string' && provider.name.length > 0
}
