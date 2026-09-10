import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Avatar, Badge, Button, EmptyState, Field, HudPanel, Icon, ModalOverlay, Notice, PageIntro, PasswordField, useModalFocus } from '@chenxing/ui'
import {
  bindLinkedAccount,
  listAccountProviders,
  listLinkedAccounts,
  refreshLinkedAccount,
  unlinkLinkedAccount,
  type AccountProvider,
  type ExternalIdentityExtension,
  type ExternalIdentityExtensionField,
  type LinkedAccount,
} from '../../api'
import { useMutationLock } from '../../use-mutation-lock'
import { ConsoleLayout } from '../../components/shells'
import { Link } from '../../router'
import { formatDate } from '../../data'

type NoticeState = { text: string; tone: 'success' | 'warning' }
type LoadState = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; message: string }
type DialogState =
  | { kind: 'bind'; provider: AccountProvider }
  | { kind: 'unlink'; account: LinkedAccount }

/**
 * 已连接账号聚合页（Issue #706）。
 *
 * 一个端点（GET /api/v1/auth/linked-accounts）同时返回 OAuth 外部身份
 * （kind=oauth_identity，只读本地快照，刷新不可用）与业务服务账号
 * （kind=service_account，当前为 CLtermux，支持真实刷新、凭据绑定与密码复验解绑）。
 * 契约字段经 response guard 校验，任何半截数据都会落到整体错误态而不是渲染错误卡片。
 */
export function OAuthIdentitiesPage() {
  const [accounts, setAccounts] = useState<LinkedAccount[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [providers, setProviders] = useState<AccountProvider[]>([])
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [notice, setNotice] = useState<NoticeState | null>(null)
  const [refreshingId, setRefreshingId] = useState<string | null>(null)
  const [loadingMore, setLoadingMore] = useState(false)
  const [dialog, setDialog] = useState<DialogState | null>(null)
  const requestIdRef = useRef(0)
  const mutationLock = useMutationLock()

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    setState((current) => current.kind === 'ready' ? current : { kind: 'loading' })
    setNotice(null)
    const [accountsResult, providersResult] = await Promise.allSettled([
      listLinkedAccounts(null),
      listAccountProviders(),
    ])
    if (requestId !== requestIdRef.current) return
    if (accountsResult.status === 'fulfilled') {
      setAccounts(accountsResult.value.items)
      setNextCursor(accountsResult.value.next_cursor)
      setState({ kind: 'ready' })
    } else {
      const message = accountsResult.reason instanceof Error ? accountsResult.reason.message : '已连接账号加载失败。'
      setAccounts([])
      setNextCursor(null)
      setState({ kind: 'error', message })
      setNotice({ text: message, tone: 'warning' })
    }
    // 供应商目录失败不阻塞列表展示：降级为「暂无绑定入口」并在 Notice 中说明
    if (providersResult.status === 'fulfilled') {
      setProviders(providersResult.value.items)
    } else {
      setProviders([])
      setNotice({ text: '绑定入口暂时不可用，列表数据不受影响。', tone: 'warning' })
    }
  }, [])

  useEffect(() => {
    void load()
    return () => { requestIdRef.current += 1 }
  }, [load])

  async function loadMore() {
    if (!nextCursor || loadingMore || state.kind !== 'ready') return
    setLoadingMore(true)
    setNotice(null)
    try {
      const response = await listLinkedAccounts(nextCursor)
      setAccounts((current) => {
        const known = new Set(current.map((account) => account.id))
        return [...current, ...response.items.filter((account) => !known.has(account.id))]
      })
      setNextCursor(response.next_cursor)
    } catch (error) {
      setNotice({ text: error instanceof Error ? error.message : '加载更多失败，请重试。', tone: 'warning' })
    } finally {
      setLoadingMore(false)
    }
  }

  async function refreshAccount(account: LinkedAccount) {
    if (refreshingId) return
    const requestId = ++requestIdRef.current
    setRefreshingId(account.id)
    setNotice(null)
    try {
      const refreshed = await refreshLinkedAccount(account.id)
      if (requestId !== requestIdRef.current) return
      setAccounts((current) => current.map((item) => item.id === account.id ? refreshed : item))
      if (refreshed.sync.status === 'failed') {
        setNotice({ text: `${refreshed.provider.name} 数据已保留上一次成功快照。`, tone: 'warning' })
      } else {
        setNotice({ text: `${refreshed.provider.name} 数据已刷新。`, tone: 'success' })
      }
    } catch (error) {
      if (requestId !== requestIdRef.current) return
      const message = error instanceof Error ? error.message : '账号同步失败，已保留上一次成功数据。'
      setAccounts((current) => current.map((item) => item.id === account.id
        ? { ...item, sync: { ...item.sync, status: 'failed', error: message } }
        : item))
      setNotice({ text: message, tone: 'warning' })
    } finally {
      if (requestId === requestIdRef.current) setRefreshingId(null)
    }
  }

  async function submitBind(provider: AccountProvider, publicKey: string, privateKey: string): Promise<boolean> {
    return (await mutationLock.run(async () => {
      setNotice(null)
      try {
        const bound = await bindLinkedAccount(provider.id, { public_key: publicKey, private_key: privateKey })
        setAccounts((current) => {
          const known = new Set(current.map((account) => account.id))
          return known.has(bound.id)
            ? current.map((account) => account.id === bound.id ? bound : account)
            : [bound, ...current]
        })
        setNotice({ text: `${provider.name} 绑定成功。`, tone: 'success' })
        return true
      } catch (error) {
        setNotice({ text: error instanceof Error ? error.message : '绑定失败，请核对凭据后重试。', tone: 'warning' })
        return false
      }
    })) === true
  }

  async function submitUnlink(account: LinkedAccount, password: string): Promise<boolean> {
    return (await mutationLock.run(async () => {
      setNotice(null)
      try {
        await unlinkLinkedAccount(account.id, { password })
        setAccounts((current) => current.filter((item) => item.id !== account.id))
        setNotice({ text: `${account.provider.name} 已解除绑定。`, tone: 'success' })
        return true
      } catch (error) {
        setNotice({ text: error instanceof Error ? error.message : '解除绑定失败，请重试。', tone: 'warning' })
        return false
      }
    })) === true
  }

  const initialLoading = state.kind === 'loading'
  const showTopNotice = notice !== null && !(state.kind === 'error' && accounts.length === 0)
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Account · 已连接账号"
        title="已连接账号"
        description="集中查看已绑定的外部身份与业务服务账号（如 CLtermux），管理快照同步与绑定关系。"
        action={<Button variant="ghost" icon="refresh-cw" disabled={initialLoading || refreshingId !== null || mutationLock.busy} onClick={() => void load()}>刷新</Button>}
      />
      {showTopNotice ? <div className="mb-4"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}
      {initialLoading ? <LoadingPanel /> : null}
      {state.kind === 'error' ? (
        <HudPanel><Notice tone="warning">无法加载已连接账号。{state.message} <button type="button" className="chenxing-link ml-2" onClick={() => void load()}>重试</button></Notice></HudPanel>
      ) : null}
      {state.kind === 'ready' && accounts.length === 0 && providers.length === 0 ? (
        <HudPanel>
          <EmptyState
            icon="fingerprint"
            title="暂无已连接账号"
            description="绑定外部身份或业务服务账号后，可以在这里查看供应商返回的账号资料。"
            action={<Link className="chenxing-btn-primary mt-2" to="/console/profile">前往账户绑定</Link>}
          />
        </HudPanel>
      ) : null}
      {state.kind === 'ready' ? (
        <HudPanel as="section" className="mb-4 !p-5 sm:!p-6" aria-label="绑定业务账号">
          {providers.length ? (
            providers.map((provider) => (
              <div key={provider.id} className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="chenxing-h3">绑定 {provider.name}</h2>
                  <p className="chenxing-caption mt-1">输入 {provider.name} 公钥与私钥完成绑定；凭据仅用于当次校验，不会被存储。</p>
                </div>
                <Button
                  variant="primary"
                  icon="link"
                  aria-label={`绑定 ${provider.name}`}
                  disabled={mutationLock.busy || refreshingId !== null}
                  onClick={() => setDialog({ kind: 'bind', provider })}
                >
                  绑定 {provider.name}
                </Button>
              </div>
            ))
          ) : (
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="chenxing-h3">绑定业务账号</h2>
                <p className="chenxing-caption mt-1">当前平台尚未开放业务账号绑定；启用后，绑定入口会自动出现在这里。</p>
              </div>
              <Badge>暂无可用绑定</Badge>
            </div>
          )}
        </HudPanel>
      ) : null}
      {accounts.length ? (
        <div className="space-y-4">
          {accounts.map((account) => (
            <LinkedAccountCard
              key={account.id}
              account={account}
              refreshing={refreshingId === account.id}
              busy={mutationLock.busy}
              onRefresh={() => void refreshAccount(account)}
              onUnlink={() => setDialog({ kind: 'unlink', account })}
            />
          ))}
        </div>
      ) : null}
      {nextCursor ? (
        <div className="mt-4 flex justify-center">
          <Button variant="ghost" icon="arrow-down" disabled={loadingMore || refreshingId !== null || mutationLock.busy} onClick={() => void loadMore()}>
            {loadingMore ? '加载中…' : '加载更多'}
          </Button>
        </div>
      ) : null}
      {dialog?.kind === 'bind' ? (
        <BindDialog
          provider={dialog.provider}
          busy={mutationLock.busy}
          onCancel={() => setDialog(null)}
          onSubmit={submitBind}
        />
      ) : null}
      {dialog?.kind === 'unlink' ? (
        <UnlinkDialog
          account={dialog.account}
          busy={mutationLock.busy}
          onCancel={() => setDialog(null)}
          onSubmit={submitUnlink}
        />
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

function LinkedAccountCard({ account, refreshing, busy, onRefresh, onUnlink }: {
  account: LinkedAccount
  refreshing: boolean
  busy: boolean
  onRefresh: () => void
  onUnlink: () => void
}) {
  const accountName = account.display.name || account.display.email || account.uid || '外部账号'
  const avatar = safeImageSource(account.display.avatar_url)
  const providerIcon = safeImageSource(account.provider.icon_url)
  const isServiceAccount = account.kind === 'service_account'
  const canRefresh = account.capabilities.can_refresh
  return (
    <HudPanel as="article" className="!p-5 sm:!p-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <span className="flex h-12 w-12 shrink-0 items-center justify-center overflow-hidden rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border-strong)] bg-[var(--chenxing-cyan-soft)] text-[var(--chenxing-cyan)]">
            {providerIcon ? <img src={providerIcon} alt="" className="h-full w-full object-cover" /> : <Icon name={providerIconName(account)} size={21} />}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="chenxing-h3 truncate" title={account.provider.name}>{account.provider.name}</h2>
              <AccountKindBadge kind={account.kind} />
              <AccountStatus account={account} />
            </div>
            <p className="chenxing-caption mt-1 chenxing-mono truncate" title={account.provider.id}>{account.provider.id}</p>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          {canRefresh ? (
            <Button variant="ghost" icon="refresh-cw" aria-label={`刷新 ${account.provider.name} 数据`} disabled={refreshing || busy} onClick={onRefresh}>{refreshing ? '同步中…' : '刷新数据'}</Button>
          ) : null}
          {isServiceAccount ? (
            <Button variant="danger" icon="unlink" aria-label={`解除 ${account.provider.name} 绑定`} disabled={refreshing || busy} onClick={onUnlink}>解绑</Button>
          ) : null}
        </div>
      </header>

      <div className="mt-5 flex items-center gap-3 border-t border-[var(--chenxing-border)] pt-5">
        <Avatar src={avatar} name={accountName} className="h-12 w-12 shrink-0" />
        <div className="min-w-0">
          <p className="chenxing-body truncate font-semibold" title={accountName}>{accountName}</p>
          <p className="chenxing-caption">{isServiceAccount ? '业务服务账号' : 'OAuth 登录身份'}</p>
        </div>
      </div>

      <dl className="mt-5 grid min-w-0 grid-cols-1 gap-x-6 gap-y-4 border-t border-[var(--chenxing-border)] pt-5 sm:grid-cols-2">
        <Detail label="邮箱">{account.display.email || '—'}</Detail>
        {account.uid ? <Detail label="业务 UID"><span className="chenxing-mono text-xs">{account.uid}</span></Detail> : null}
        {account.subject_hint ? <Detail label="Subject 标识"><span className="chenxing-mono text-xs">{redactSubject(account.subject_hint)}</span></Detail> : null}
        <Detail label="绑定时间">{formatDate(account.linked_at)}</Detail>
        <Detail label="最近同步">{formatDate(account.sync.last_success_at ?? account.linked_at)}</Detail>
      </dl>

      {account.sync.status === 'failed' ? <div className="mt-5 flex items-start gap-2 border-t border-[var(--chenxing-border)] pt-4"><Icon name="circle-alert" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-warning)]" /><p className="chenxing-caption">供应商暂时不可用，页面保留上一次成功数据。{account.sync.error ? ` ${account.sync.error}` : ''}</p></div> : null}
      {account.account_status !== 'active' ? <div className="mt-5 flex items-start gap-2 border-t border-[var(--chenxing-border)] pt-4"><Icon name="info" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-warning)]" /><p className="chenxing-caption">该账号当前状态为「{accountStatusLabel(account.account_status)}」，部分能力可能受限；绑定关系保持有效。</p></div> : null}
      {account.extensions.length ? <Extensions extensions={account.extensions} /> : null}
      <footer className="mt-5 border-t border-[var(--chenxing-border)] pt-4"><Link className="chenxing-link inline-flex items-center gap-1" to="/console/profile">管理绑定 <Icon name="arrow-right" size={13} /></Link></footer>
    </HudPanel>
  )
}

function AccountKindBadge({ kind }: { kind: LinkedAccount['kind'] }) {
  if (kind === 'service_account') return <Badge tone="gold">服务账号</Badge>
  return <Badge>OAuth 身份</Badge>
}

function accountStatusLabel(status: string): string {
  if (status === 'disabled') return '已停用'
  if (status === 'missing') return '已注销或不存在'
  if (status === 'unknown') return '未知'
  return status
}

function AccountStatus({ account }: { account: LinkedAccount }) {
  if (account.sync.status === 'failed') return <Badge tone="warning">同步失败</Badge>
  if (account.sync.status === 'never') return <Badge>未同步</Badge>
  if (account.account_status === 'unknown') return <Badge>状态未知</Badge>
  if (account.account_status && account.account_status !== 'active') return <Badge tone="warning">{accountStatusLabel(account.account_status)}</Badge>
  return <Badge tone="success">已绑定</Badge>
}

function BindDialog({ provider, busy, onCancel, onSubmit }: {
  provider: AccountProvider
  busy: boolean
  onCancel: () => void
  onSubmit: (provider: AccountProvider, publicKey: string, privateKey: string) => Promise<boolean>
}) {
  const [publicKey, setPublicKey] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [fieldError, setFieldError] = useState<string | null>(null)
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: '#bind-public-key',
    escapeDisabled: busy,
  })

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    if (!publicKey.trim() || !privateKey.trim()) {
      setFieldError('请填写公钥和私钥。')
      return
    }
    setFieldError(null)
    const succeeded = await onSubmit(provider, publicKey.trim(), privateKey.trim())
    if (succeeded) onCancel()
  }

  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel
        ref={containerRef}
        as="form"
        role="dialog"
        aria-modal="true"
        aria-labelledby="bind-account-title"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-lg"
        onSubmit={(event) => { void handleSubmit(event) }}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-cyan)]">// Bind Service Account</p>
            <h2 id="bind-account-title" className="chenxing-h2 mt-2">绑定 {provider.name}</h2>
            <p className="chenxing-caption mt-2">凭据只用于本次校验，平台不会保存。重复提交同一个账号会直接返回已有绑定。</p>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>
        <div className="mt-5 space-y-4">
          <Field
            id="bind-public-key"
            label={`${provider.name} 公钥`}
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            errorText={fieldError && !publicKey.trim() ? fieldError : undefined}
            disabled={busy}
            autoComplete="off"
          />
          <Field
            id="bind-private-key"
            label={`${provider.name} 私钥`}
            value={privateKey}
            onChange={(event) => setPrivateKey(event.target.value)}
            errorText={fieldError && !privateKey.trim() ? fieldError : undefined}
            disabled={busy}
            autoComplete="off"
          />
        </div>
        <div className="mt-5 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button type="submit" variant="primary" icon="link" disabled={busy}>{busy ? '绑定中…' : `绑定 ${provider.name}`}</Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
}

function UnlinkDialog({ account, busy, onCancel, onSubmit }: {
  account: LinkedAccount
  busy: boolean
  onCancel: () => void
  onSubmit: (account: LinkedAccount, password: string) => Promise<boolean>
}) {
  const [password, setPassword] = useState('')
  const containerRef = useModalFocus<HTMLFormElement>(onCancel, {
    initialFocusSelector: '#unlink-account-password',
    escapeDisabled: busy,
  })

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    if (busy) return
    const succeeded = await onSubmit(account, password)
    if (succeeded) onCancel()
  }

  return (
    <ModalOverlay onDismiss={() => { if (!busy) onCancel() }}>
      <HudPanel
        ref={containerRef}
        as="form"
        role="dialog"
        aria-modal="true"
        aria-labelledby="unlink-account-title"
        tabIndex={-1}
        className="relative z-[var(--chenxing-z-dialog)] my-auto w-full max-w-md"
        onSubmit={(event) => { void handleSubmit(event) }}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="chenxing-mono text-[11px] uppercase tracking-[0.2em] text-[var(--chenxing-error)]">// Re-authentication</p>
            <h2 id="unlink-account-title" className="chenxing-h2 mt-2">解除 {account.provider.name}</h2>
          </div>
          <button type="button" className="chenxing-icon-btn shrink-0" aria-label="关闭" onClick={onCancel} disabled={busy}>
            <Icon name="x" size={17} />
          </button>
        </div>
        <p className="chenxing-caption mt-4">这是敏感安全操作。请输入当前密码确认身份；解除后，供应商那边的登录不受影响，但平台侧不再保留绑定关系。</p>
        <div className="mt-5"><PasswordField id="unlink-account-password" label="当前密码" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} disabled={busy} /></div>
        <div className="mt-5 flex flex-wrap justify-end gap-3">
          <Button type="button" variant="ghost" onClick={onCancel} disabled={busy}>取消</Button>
          <Button type="submit" variant="danger" icon="unlink" disabled={busy}>{busy ? '处理中…' : '确认解除绑定'}</Button>
        </div>
      </HudPanel>
    </ModalOverlay>
  )
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

function providerIconName(account: LinkedAccount): string {
  const value = `${account.provider.id} ${account.provider.name}`.toLowerCase()
  if (value.includes('cltermux')) return 'terminal'
  if (value.includes('github') || value.includes('gitlab') || value.includes('gitee')) return 'github'
  if (value.includes('google') || value.includes('microsoft')) return 'badge-check'
  if (value.includes('oidc') || value.includes('saml') || value.includes('enterprise')) return 'server'
  return 'globe'
}
