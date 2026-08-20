import { useEffect, useMemo, useState } from 'react'
import { apiFetch, type ExternalIdentity, type ExternalIdentityListResponse, type PublicExternalProvider } from '../../api'
import { useDrawerFocus } from '../../components/drawer'
import { Badge, Button, HudPanel, Icon, PasswordField } from '../../components/ui'
import { safeRedirectTarget } from '../../safe-redirect'
import type { MessageTone } from './profile-avatar'

type NoticeState = { text: string; tone: MessageTone }
type ExternalBindingStart = { authorization_url: string }

type ExternalIdentitiesProps = {
  userEmail: string
  busy: string | null
  onBusy: (value: string | null) => void
  onNotice: (notice: NoticeState | null) => void
}

type ProviderBinding = {
  slug: string
  name: string
  identity: ExternalIdentity | null
}

export function ExternalIdentities({ userEmail, busy, onBusy, onNotice }: ExternalIdentitiesProps) {
  const [identities, setIdentities] = useState<ExternalIdentity[]>([])
  const [providers, setProviders] = useState<PublicExternalProvider[]>([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [unlinking, setUnlinking] = useState<ExternalIdentity | null>(null)
  const [password, setPassword] = useState('')

  async function load(): Promise<void> {
    setLoading(true)
    setLoadError(null)
    const [identityResult, providerResult] = await Promise.allSettled([
      apiFetch<ExternalIdentityListResponse>('/api/v1/auth/external-identities'),
      apiFetch<PublicExternalProvider[]>('/api/v1/auth/external-providers', { redirectOn401: false }),
    ])
    const errors: string[] = []
    if (identityResult.status === 'fulfilled') {
      setIdentities(Array.isArray(identityResult.value.items) ? identityResult.value.items : [])
    } else {
      errors.push(identityResult.reason instanceof Error ? identityResult.reason.message : '已绑定身份加载失败。')
    }
    if (providerResult.status === 'fulfilled') {
      setProviders(providerResult.value.filter(isProvider))
    } else {
      errors.push(providerResult.reason instanceof Error ? providerResult.reason.message : '可用身份源加载失败。')
    }
    if (errors.length) {
      const message = errors.join(' ')
      setLoadError(message)
      onNotice({ text: message, tone: 'warning' })
    }
    setLoading(false)
  }

  useEffect(() => { void load() }, [])

  const bindings = useMemo(() => mergeProviderBindings(providers, identities), [providers, identities])
  const boundCount = bindings.filter((binding) => binding.identity).length + 1

  async function startBinding(slug: string): Promise<void> {
    if (busy) return
    onBusy(`bind-${slug}`)
    onNotice(null)
    try {
      const result = await apiFetch<ExternalBindingStart>(`/api/v1/auth/external-identities/${encodeURIComponent(slug)}/bind`, {
        method: 'POST',
      })
      const target = bindingRedirectTarget(result)
      if (!target) throw new Error('外部授权入口不可用，请稍后重试。')
      window.location.assign(target)
    } catch (error) {
      onNotice({ text: error instanceof Error ? error.message : '无法开始外部账户绑定。', tone: 'warning' })
      onBusy(null)
    }
  }

  async function unlink(): Promise<void> {
    if (!unlinking || busy) return
    if (!password) {
      onNotice({ text: '请输入当前密码完成重新认证。', tone: 'warning' })
      return
    }
    const identity = unlinking
    onBusy(`unlink-${identity.provider}`)
    onNotice(null)
    try {
      await apiFetch<void>(`/api/v1/auth/external-identities/${encodeURIComponent(identity.provider)}`, {
        method: 'DELETE',
        redirectOn401: false, body: JSON.stringify({ password }),
      })
      setIdentities((current) => current.filter((item) => item.provider !== identity.provider))
      setUnlinking(null)
      setPassword('')
      onNotice({ text: `${identity.provider_name} 已解除绑定。`, tone: 'success' })
      await load()
    } catch (error) {
      onNotice({ text: error instanceof Error ? error.message : '解除外部账户绑定失败。', tone: 'warning' })
    } finally {
      onBusy(null)
    }
  }

  return (
    <div aria-labelledby="account-bindings-heading">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="account-bindings-heading" className="chenxing-h3">登录身份</h3>
          <p className="chenxing-caption mt-1 max-w-2xl">绑定后可以使用对应身份源登录。新的登录提供方启用后会自动出现在这里。</p>
        </div>
        <Badge tone="success">{loading ? '读取中' : `${boundCount} 个可用身份`}</Badge>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <IdentityCard
          icon="mail"
          name="邮箱"
          value={userEmail}
          status={<Badge tone="success">主身份</Badge>}
        />
        {loading ? <LoadingBindingRows /> : bindings.map((binding) => (
          <IdentityCard
            key={binding.slug}
            icon={providerIcon(binding.slug, binding.name)}
            iconTone={providerIconTone(binding.slug, binding.name)}
            name={binding.name}
            value={binding.identity?.email || '尚未绑定'}
            status={binding.identity ? <Badge tone="success">已绑定</Badge> : <Badge>可绑定</Badge>}
            action={binding.identity ? (
              <Button
                className="min-h-11"
                variant="danger"
                icon="unlink"
                aria-label={`解除 ${binding.name} 绑定`}
                disabled={busy !== null}
                onClick={() => { setUnlinking(binding.identity); setPassword('') }}
              >
                解除
              </Button>
            ) : (
              <Button
                className="min-h-11"
                variant="ghost"
                icon="link"
                aria-label={`绑定 ${binding.name}`}
                disabled={busy !== null}
                onClick={() => void startBinding(binding.slug)}
              >
                {busy === `bind-${binding.slug}` ? '跳转中…' : '绑定'}
              </Button>
            )}
          />
        ))}
      </div>

      {loadError ? (
        <div className="mt-4 flex items-start gap-2 border-t border-[var(--chenxing-border)] pt-4">
          <Icon name="circle-alert" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-warning)]" />
          <p className="chenxing-caption">登录身份暂时不可用。{loadError} <button type="button" className="chenxing-link ml-2" onClick={() => void load()}>重试</button></p>
        </div>
      ) : null}

      {!loading && !loadError && bindings.length === 0 ? (
        <div className="mt-4 flex items-start gap-2 border-t border-[var(--chenxing-border)] pt-4">
          <Icon name="info" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-muted-foreground)]" />
          <p className="chenxing-caption">管理员尚未启用其他登录身份。启用新的 OAuth/OIDC 提供方后，本列表会自动扩展。</p>
        </div>
      ) : null}

      {unlinking ? (
        <UnlinkDialog
          identity={unlinking}
          password={password}
          busy={busy !== null}
          onPassword={setPassword}
          onCancel={() => { setUnlinking(null); setPassword('') }}
          onConfirm={() => void unlink()}
        />
      ) : null}
    </div>
  )
}

function IdentityCard({ icon, iconTone = 'cyan', name, value, status, action }: {
  icon: string
  iconTone?: 'cyan' | 'gold' | 'neutral'
  name: string
  value: string
  status: React.ReactNode
  action?: React.ReactNode
}) {
  const iconToneClass = iconTone === 'gold'
    ? 'text-[var(--chenxing-gold)]'
    : iconTone === 'neutral'
      ? 'text-[var(--chenxing-foreground)]'
      : 'text-[var(--chenxing-cyan)]'
  return (
    <section className="flex min-h-[92px] items-center justify-between gap-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] p-4 transition-colors duration-200 hover:border-[var(--chenxing-border-strong)]">
      <div className="flex min-w-0 items-center gap-3">
        <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] ${iconToneClass}`}>
          <Icon name={icon} size={18} />
        </span>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="chenxing-body text-sm font-semibold">{name}</h4>
            {status}
          </div>
          <p className="chenxing-caption mt-1 truncate" title={value}>{value}</p>
        </div>
      </div>
      {action ? <div className="shrink-0">{action}</div> : null}
    </section>
  )
}

function LoadingBindingRows() {
  return (
    <>
      {[0, 1].map((item) => (
        <div key={item} className="flex min-h-[92px] animate-pulse items-center gap-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.28)] p-4" aria-hidden="true">
          <span className="h-10 w-10 rounded-[var(--chenxing-radius-md)] bg-[var(--chenxing-muted)]" />
          <span className="h-4 w-32 rounded bg-[var(--chenxing-muted)]" />
        </div>
      ))}
    </>
  )
}

function UnlinkDialog({ identity, password, busy, onPassword, onCancel, onConfirm }: {
  identity: ExternalIdentity
  password: string
  busy: boolean
  onPassword: (value: string) => void
  onCancel: () => void
  onConfirm: () => void
}) {
  const containerRef = useDrawerFocus(onCancel, busy)

  return (
    <div className="fixed inset-0 z-[var(--chenxing-z-overlay)] flex items-center justify-center bg-black/70 p-4" role="presentation" onMouseDown={(event) => { if (!busy && event.target === event.currentTarget) onCancel() }}>
      <HudPanel ref={containerRef} as="section" role="dialog" aria-modal="true" aria-labelledby="unlink-external-title" aria-busy={busy || undefined} tabIndex={-1} className="relative z-[var(--chenxing-z-dialog)] w-full max-w-md">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Re-authentication</p>
            <h2 id="unlink-external-title" className="chenxing-h2 mt-2">解除 {identity.provider_name}</h2>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onCancel} disabled={busy}><Icon name="x" size={17} /></button>
        </div>
        <p className="chenxing-caption mt-4">这是敏感安全操作。请输入当前密码确认身份，外部账户不会再用于登录。</p>
        <div className="mt-5"><PasswordField label="当前密码" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} /></div>
        <div className="mt-5 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button type="button" variant="danger" icon="unlink" onClick={onConfirm} disabled={busy}>{busy ? '处理中…' : '确认解除绑定'}</Button>
        </div>
      </HudPanel>
    </div>
  )
}

function mergeProviderBindings(providers: PublicExternalProvider[], identities: ExternalIdentity[]): ProviderBinding[] {
  const identityByProvider = new Map(identities.map((identity) => [identity.provider, identity]))
  const bindings = providers.map((provider) => ({
    slug: provider.slug,
    name: provider.name,
    identity: identityByProvider.get(provider.slug) ?? null,
  }))
  const known = new Set(bindings.map((binding) => binding.slug))
  for (const identity of identities) {
    if (!known.has(identity.provider)) {
      bindings.push({ slug: identity.provider, name: identity.provider_name, identity })
    }
  }
  return bindings
}

function bindingRedirectTarget(value: unknown): string | null {
  if (typeof value !== 'object' || value === null) return null
  const candidate = value as { authorization_url?: unknown }
  return typeof candidate.authorization_url === 'string' ? safeRedirectTarget(candidate.authorization_url) : null
}

function isProvider(provider: PublicExternalProvider): boolean {
  return typeof provider?.slug === 'string' && provider.slug.length > 0 && typeof provider?.name === 'string' && provider.name.length > 0
}

function providerIcon(slug: string, name: string): string {
  const identity = `${slug} ${name}`.toLowerCase()
  if (identity.includes('github') || identity.includes('gitlab') || identity.includes('gitee')) return 'github'
  if (identity.includes('chenxing') || identity.includes('辰星')) return 'shield-check'
  if (identity.includes('oidc') || identity.includes('saml') || identity.includes('enterprise') || identity.includes('企业')) return 'server'
  if (identity.includes('google') || identity.includes('microsoft')) return 'badge-check'
  return 'globe'
}

function providerIconTone(slug: string, name: string): 'cyan' | 'gold' | 'neutral' {
  const identity = `${slug} ${name}`.toLowerCase()
  if (identity.includes('chenxing') || identity.includes('辰星')) return 'gold'
  if (identity.includes('github') || identity.includes('gitlab') || identity.includes('gitee')) return 'neutral'
  return 'cyan'
}
