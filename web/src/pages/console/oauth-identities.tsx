import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react'
import { Avatar, Badge, Button, EmptyState, HudPanel, Icon, Notice, PageIntro } from '@chenxing/ui'
import { apiFetch, type ExternalIdentity, type ExternalIdentityExtension, type ExternalIdentityExtensionField, type ExternalIdentityListResponse } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Link } from '../../router'
import { formatDate } from '../../data'

type NoticeState = { text: string; tone: 'success' | 'warning' }
type LoadState = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; message: string }

export function OAuthIdentitiesPage() {
  const [identities, setIdentities] = useState<ExternalIdentity[]>([])
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [notice, setNotice] = useState<NoticeState | null>(null)
  const [refreshingProvider, setRefreshingProvider] = useState<string | null>(null)
  const requestIdRef = useRef(0)

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    setState((current) => current.kind === 'ready' ? current : { kind: 'loading' })
    setNotice(null)
    try {
      const response = await apiFetch<ExternalIdentityListResponse>('/api/v1/auth/external-identities', { redirectOn401: false })
      if (requestId !== requestIdRef.current) return
      setIdentities(response.items)
      setState({ kind: 'ready' })
    } catch (error) {
      if (requestId !== requestIdRef.current) return
      const message = error instanceof Error ? error.message : 'OAuth 账号加载失败。'
      setState({ kind: 'error', message })
      setNotice({ text: message, tone: 'warning' })
    }
  }, [])

  useEffect(() => {
    void load()
    return () => { requestIdRef.current += 1 }
  }, [load])

  async function refreshProvider(identity: ExternalIdentity) {
    if (refreshingProvider) return
    const requestId = ++requestIdRef.current
    setRefreshingProvider(identity.provider)
    setNotice(null)
    try {
      // The provider adapter owns the server-side refresh. Until that adapter is deployed,
      // re-reading the same authenticated endpoint keeps this page compatible with older servers.
      const response = await apiFetch<ExternalIdentityListResponse>('/api/v1/auth/external-identities', { redirectOn401: false })
      if (requestId !== requestIdRef.current) return
      const refreshed = response.items.find((item) => item.provider === identity.provider)
      if (!refreshed) throw new Error('该 OAuth 账号暂时无法同步，已保留上一次成功数据。')
      setIdentities((current) => current.map((item) => item.provider === identity.provider ? refreshed : item))
      setState({ kind: 'ready' })
      setNotice({ text: `${identity.provider_name} 数据已刷新。`, tone: 'success' })
    } catch (error) {
      if (requestId !== requestIdRef.current) return
      const message = error instanceof Error ? error.message : 'OAuth 账号同步失败，已保留上一次成功数据。'
      setIdentities((current) => current.map((item) => item.provider === identity.provider
        ? { ...item, sync_status: 'failed', sync_error: message }
        : item))
      setState((current) => current.kind === 'error' ? { kind: 'ready' } : current)
      setNotice({ text: message, tone: 'warning' })
    } finally {
      if (requestId === requestIdRef.current) setRefreshingProvider(null)
    }
  }

  const initialLoading = state.kind === 'loading' && identities.length === 0
  const showTopNotice = notice !== null && !(state.kind === 'error' && identities.length === 0)
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Account · OAuth"
        title="OAuth 登录账号"
        description="集中查看已绑定的外部身份、标准资料和供应商扩展信息。"
        action={<Button variant="ghost" icon="refresh-cw" disabled={initialLoading || refreshingProvider !== null} onClick={() => void load()}>刷新</Button>}
      />
      {showTopNotice ? <div className="mb-4"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}
      {initialLoading ? <LoadingPanel /> : null}
      {state.kind === 'error' && identities.length === 0 ? (
        <HudPanel><Notice tone="warning">无法加载 OAuth 登录账号。{state.message} <button type="button" className="chenxing-link ml-2" onClick={() => void load()}>重试</button></Notice></HudPanel>
      ) : null}
      {state.kind === 'ready' && identities.length === 0 ? (
        <HudPanel>
          <EmptyState
            icon="fingerprint"
            title="暂无 OAuth 登录账号"
            description="绑定外部身份后，可以在这里查看供应商返回的账号资料。"
            action={<Link className="chenxing-btn-primary mt-2" to="/console/profile">前往账户绑定</Link>}
          />
        </HudPanel>
      ) : null}
      {identities.length ? (
        <div className="space-y-4">
          {identities.map((identity) => (
            <IdentityDetailsCard
              key={identity.provider}
              identity={identity}
              refreshing={refreshingProvider === identity.provider}
              onRefresh={() => void refreshProvider(identity)}
            />
          ))}
        </div>
      ) : null}
    </ConsoleLayout>
  )
}

function LoadingPanel() {
  return (
    <HudPanel aria-busy="true" className="space-y-4">
      {[0, 1].map((item) => <div key={item} className="flex min-h-32 animate-pulse items-center gap-4 border-b border-[var(--chenxing-border)] pb-4 last:border-b-0 last:pb-0" aria-hidden="true"><span className="h-12 w-12 rounded-full bg-[var(--chenxing-muted)]" /><span className="h-4 w-48 rounded bg-[var(--chenxing-muted)]" /></div>)}
    </HudPanel>
  )
}

function IdentityDetailsCard({ identity, refreshing, onRefresh }: { identity: ExternalIdentity; refreshing: boolean; onRefresh: () => void }) {
  const accountName = identity.account_name || identity.name || identity.email || '外部账号'
  const syncStatus = identity.sync_status || 'success'
  const syncFailed = syncStatus === 'failed'
  const avatar = safeImageSource(identity.avatar_url)
  const providerIcon = safeImageSource(identity.provider_icon)
  return (
    <HudPanel as="article" className="!p-5 sm:!p-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border-strong)] bg-[var(--chenxing-cyan-soft)] text-[var(--chenxing-cyan)]">
            {providerIcon ? <img src={providerIcon} alt="" className="h-full w-full object-cover" /> : <Icon name={providerIconName(identity.provider, identity.provider_name)} size={21} />}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="chenxing-h3 truncate" title={identity.provider_name}>{identity.provider_name}</h2>
              <IdentityStatus syncStatus={syncStatus} status={identity.status} />
            </div>
            <p className="chenxing-caption mt-1 chenxing-mono truncate" title={identity.provider}>{identity.provider}</p>
          </div>
        </div>
        <Button variant="ghost" icon="refresh-cw" aria-label={`刷新 ${identity.provider_name} 数据`} disabled={refreshing} onClick={onRefresh}>{refreshing ? '同步中…' : '刷新数据'}</Button>
      </header>

      <div className="mt-5 flex items-center gap-3 border-t border-[var(--chenxing-border)] pt-5">
        <Avatar src={avatar} name={accountName} className="h-12 w-12 shrink-0" />
        <div className="min-w-0">
          <p className="chenxing-body truncate font-semibold" title={accountName}>{accountName}</p>
          <p className="chenxing-caption">供应商账号资料</p>
        </div>
      </div>

      <dl className="mt-5 grid min-w-0 grid-cols-1 gap-x-6 gap-y-4 border-t border-[var(--chenxing-border)] pt-5 sm:grid-cols-2">
        <Detail label="邮箱">{identity.email || '—'}</Detail>
        <Detail label="Subject 标识"><span className="chenxing-mono text-xs">{redactSubject(identity.subject_hint)}</span></Detail>
        <Detail label="绑定时间">{formatDate(identity.linked_at)}</Detail>
        <Detail label="最近同步">{formatDate(identity.last_synced_at ?? identity.linked_at)}</Detail>
      </dl>

      {syncFailed ? <div className="mt-5 flex items-start gap-2 border-t border-[var(--chenxing-border)] pt-4"><Icon name="circle-alert" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-warning)]" /><p className="chenxing-caption">供应商暂时不可用，页面保留上一次成功数据。{identity.sync_error ? ` ${identity.sync_error}` : ''}</p></div> : null}
      {identity.extensions?.length ? <Extensions extensions={identity.extensions} /> : null}
      <footer className="mt-5 border-t border-[var(--chenxing-border)] pt-4"><Link className="chenxing-link inline-flex items-center gap-1" to="/console/profile">管理绑定 <Icon name="arrow-right" size={13} /></Link></footer>
    </HudPanel>
  )
}

function IdentityStatus({ syncStatus, status }: { syncStatus: string; status?: string }) {
  if (syncStatus === 'failed') return <Badge tone="warning">同步失败</Badge>
  if (syncStatus === 'pending') return <Badge>同步中</Badge>
  if (syncStatus !== 'success') return <Badge tone="warning">同步状态未知</Badge>
  if (status && status !== 'active' && status !== 'linked') return <Badge tone="warning">账号不可用</Badge>
  return <Badge tone="success">已绑定</Badge>
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return <div className="min-w-0"><dt className="chenxing-caption">{label}</dt><dd className="chenxing-body mt-1 min-w-0 break-words text-sm">{children}</dd></div>
}

function Extensions({ extensions }: { extensions: ExternalIdentityExtension[] }) {
  const titleId = useId()
  return <section aria-labelledby={titleId} className="mt-5 border-t border-[var(--chenxing-border)] pt-5"><div className="flex items-center justify-between gap-3"><h3 id={titleId} className="chenxing-body font-semibold">供应商扩展信息</h3><Icon name="braces" size={17} className="text-[var(--chenxing-cyan)]" /></div><div className="mt-4 space-y-5">{extensions.map((extension) => <ExtensionBlock key={`${extension.namespace}:${extension.version}`} extension={extension} />)}</div></section>
}

function ExtensionBlock({ extension }: { extension: ExternalIdentityExtension }) {
  return <div><div className="flex flex-wrap items-center gap-2"><span className="chenxing-mono text-xs text-[var(--chenxing-cyan)]">{extension.namespace}</span><Badge>v{String(extension.version)}</Badge><span className="chenxing-caption">同步于 {formatDate(extension.fetched_at)}</span></div><dl className="mt-3 grid min-w-0 grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">{extension.fields.map((field) => <ExtensionField key={`${field.key}:${field.label}`} field={field} />)}</dl></div>
}

function ExtensionField({ field }: { field: ExternalIdentityExtensionField }) {
  const value = extensionValue(field)
  return <Detail label={field.label || field.key}>{value ? <ExpandableValue value={value.value} href={value.href} /> : <span className="chenxing-caption">该字段类型暂不支持展示</span>}</Detail>
}

function ExpandableValue({ value, href }: { value: string; href?: string }) {
  const [expanded, setExpanded] = useState(false)
  const id = useId()
  const long = value.length > 96
  const display = long && !expanded ? `${value.slice(0, 93)}…` : value
  const content = href ? <a className="break-all text-[var(--chenxing-cyan)] underline decoration-[var(--chenxing-cyan)]/40 underline-offset-2" href={href} target="_blank" rel="noreferrer">{display}</a> : <span className="break-words">{display}</span>
  return <div className="min-w-0">{content}{long ? <><button type="button" className="chenxing-link ml-2 text-xs" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded((current) => !current)}>{expanded ? '收起' : '查看完整值'}</button><span id={id} className={expanded ? 'mt-1 block break-words' : 'sr-only'}>完整值：{value}</span></> : null}</div>
}

function extensionValue(field: ExternalIdentityExtensionField): { value: string; href?: string } | null {
  const raw = field.value
  if (field.type === 'text' || field.type === 'status' || field.type === 'datetime') return typeof raw === 'string' ? { value: field.type === 'datetime' ? formatDate(raw) : raw } : null
  if (field.type === 'number') return typeof raw === 'number' && Number.isFinite(raw) ? { value: String(raw) } : null
  if (field.type === 'boolean') return typeof raw === 'boolean' ? { value: raw ? '是' : '否' } : null
  if (field.type === 'duration_days') return typeof raw === 'number' && Number.isFinite(raw) ? { value: `${raw} 天` } : null
  if (field.type === 'url' && typeof raw === 'string') {
    const href = safeExternalUrl(raw)
    return href ? { value: raw, href } : null
  }
  return null
}

function safeImageSource(value?: string | null): string | undefined {
  if (!value) return undefined
  try {
    const url = new URL(value, window.location.origin)
    if (url.protocol === 'https:' || (url.protocol === 'http:' && url.origin === window.location.origin)) return url.toString()
  } catch { /* malformed provider media is intentionally ignored */ }
  return undefined
}

function safeExternalUrl(value: string): string | undefined {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : undefined
  } catch { return undefined }
}

function redactSubject(value?: string | null): string {
  const subject = value?.trim()
  if (!subject) return '平台未返回可展示标识'
  if (subject.length <= 4) return '••••'
  return `${subject.slice(0, 2)}••••${subject.slice(-2)}`
}

function providerIconName(slug: string, name: string): string {
  const value = `${slug} ${name}`.toLowerCase()
  if (value.includes('github') || value.includes('gitlab') || value.includes('gitee')) return 'github'
  if (value.includes('google') || value.includes('microsoft')) return 'badge-check'
  if (value.includes('oidc') || value.includes('saml') || value.includes('enterprise')) return 'server'
  return 'globe'
}
