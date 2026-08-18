import { useEffect, useState } from 'react'
import { apiFetch, type ExternalIdentity, type ExternalIdentityListResponse, type PublicExternalProvider } from '../../api'
import { Button, EmptyState, HudPanel, Icon, PasswordField } from '../../components/ui'
import type { MessageTone } from './profile-avatar'

type NoticeState = { text: string; tone: MessageTone }

type ExternalBindingStart = { authorization_url: string }

type ExternalIdentitiesProps = {
  busy: string | null
  onBusy: (value: string | null) => void
  onNotice: (notice: NoticeState | null) => void
}

export function ExternalIdentities({ busy, onBusy, onNotice }: ExternalIdentitiesProps) {
  const [identities, setIdentities] = useState<ExternalIdentity[]>([])
  const [providers, setProviders] = useState<PublicExternalProvider[]>([])
  const [loading, setLoading] = useState(true)
  const [unlinking, setUnlinking] = useState<ExternalIdentity | null>(null)
  const [password, setPassword] = useState('')

  async function load(): Promise<void> {
    setLoading(true)
    try {
      const [identityResponse, providerResponse] = await Promise.all([
        apiFetch<ExternalIdentityListResponse>('/api/v1/auth/external-identities'),
        apiFetch<PublicExternalProvider[]>('/api/v1/auth/external-providers', { redirectOn401: false }),
      ])
      setIdentities(Array.isArray(identityResponse.items) ? identityResponse.items : [])
      setProviders(providerResponse.filter(isProvider))
    } catch (error) {
      onNotice({ text: error instanceof Error ? error.message : '外部账户状态加载失败。', tone: 'warning' })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  async function startBinding(slug: string): Promise<void> {
    if (busy) return
    onBusy(`bind-${slug}`)
    onNotice(null)
    try {
      const result = await apiFetch<ExternalBindingStart>(`/api/v1/auth/external-identities/${encodeURIComponent(slug)}/bind`, {
        method: 'POST',
      })
      if (!isExternalBindingStart(result)) throw new Error('外部授权入口不可用，请稍后重试。')
      window.location.assign(result.authorization_url)
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
        method: 'DELETE', body: JSON.stringify({ password }),
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

  const availableProviders = providers.filter((provider) => !identities.some((identity) => identity.provider === provider.slug))

  return (
    <>
      <HudPanel as="section" className="mt-5" aria-labelledby="linked-accounts-title">
        <div className="flex items-start gap-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-cyan)]"><Icon name="link" size={18} /></span>
          <div><h2 id="linked-accounts-title" className="chenxing-h2">已绑定账户</h2><p className="chenxing-caption mt-1">在此管理可用于登录的外部身份账户。</p></div>
        </div>
        {loading ? <p className="chenxing-caption mt-6 py-4">正在加载外部账户…</p> : identities.length > 0 ? (
          <div className="mt-6 divide-y divide-[var(--chenxing-border)] border-y border-[var(--chenxing-border)]">
            {identities.map((identity) => <IdentityRow key={identity.provider} identity={identity} disabled={busy !== null} onUnlink={() => { setUnlinking(identity); setPassword('') }} />)}
          </div>
        ) : <div className="mt-6"><EmptyState icon="link" title="尚未绑定外部账户" description="绑定后可使用已启用的外部身份源登录辰星通行证。" /></div>}
        {!loading && availableProviders.length > 0 ? (
          <div className="mt-6 border-t border-[var(--chenxing-border)] pt-5"><p className="chenxing-label">添加外部账户</p><div className="mt-3 flex flex-wrap gap-3">{availableProviders.map((provider) => <Button key={provider.slug} icon="globe" disabled={busy !== null} onClick={() => void startBinding(provider.slug)}>{busy === `bind-${provider.slug}` ? '跳转中…' : `绑定 ${provider.name}`}</Button>)}</div></div>
        ) : null}
      </HudPanel>
      {unlinking ? <UnlinkDialog identity={unlinking} password={password} busy={busy !== null} onPassword={setPassword} onCancel={() => { setUnlinking(null); setPassword('') }} onConfirm={() => void unlink()} /> : null}
    </>
  )
}

function IdentityRow({ identity, disabled, onUnlink }: { identity: ExternalIdentity; disabled: boolean; onUnlink: () => void }) {
  return <div className="flex flex-wrap items-center justify-between gap-4 py-4"><div className="flex min-w-0 items-center gap-3"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-cyan)]"><Icon name="globe" size={18} /></span><div className="min-w-0"><p className="chenxing-body text-sm font-semibold">{identity.provider_name}</p><p className="chenxing-caption truncate">{identity.email}</p></div></div><Button variant="danger" icon="unlink" disabled={disabled} onClick={onUnlink}>解除绑定</Button></div>
}

function UnlinkDialog({ identity, password, busy, onPassword, onCancel, onConfirm }: { identity: ExternalIdentity; password: string; busy: boolean; onPassword: (value: string) => void; onCancel: () => void; onConfirm: () => void }) {
  return <div className="fixed inset-0 z-[var(--chenxing-z-modal)] flex items-center justify-center bg-black/70 p-4" role="presentation"><HudPanel as="section" role="dialog" aria-modal="true" aria-labelledby="unlink-external-title" className="w-full max-w-md"><div className="flex items-start justify-between gap-4"><div><p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Re-authentication</p><h2 id="unlink-external-title" className="chenxing-h2 mt-2">解除 {identity.provider_name}</h2></div><button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onCancel}><Icon name="x" size={17} /></button></div><p className="chenxing-caption mt-4">这是敏感安全操作。请输入当前密码确认身份，外部账户不会再用于登录。</p><div className="mt-5"><PasswordField label="当前密码" autoComplete="current-password" value={password} onChange={(event) => onPassword(event.target.value)} /></div><div className="mt-5 flex flex-wrap justify-end gap-3"><Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button><Button type="button" variant="danger" icon="unlink" onClick={onConfirm} disabled={busy}>{busy ? '处理中…' : '确认解除绑定'}</Button></div></HudPanel></div>
}

function isExternalBindingStart(value: unknown): value is ExternalBindingStart {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as { authorization_url?: unknown }
  return typeof candidate.authorization_url === 'string' && candidate.authorization_url.length > 0
}

function isProvider(provider: PublicExternalProvider): boolean {
  return typeof provider?.slug === 'string' && provider.slug.length > 0 && typeof provider?.name === 'string' && provider.name.length > 0
}
