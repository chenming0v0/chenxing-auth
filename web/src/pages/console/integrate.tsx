import { useCallback, useEffect, useId, useRef, useState } from 'react'
import { apiFetch, type ClientInput, type OwnedOAuthClient, type RegisteredOwnedOAuthClient } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Button, CopyValue, DataTable, DataTableRow, EmptyState, HudPanel, Icon, Notice, RowAction, RowActions, TablePanel } from '@chenxing/ui'
import { AppRegisterDrawer } from './app-register-drawer'
import { formatQuota, newIdempotencyKey } from './developer-shared'
import { OfficialCallbackBlock, officialCallbackUrl, useIssuer, type OfficialCallbackState } from './official-callback'
import { MAX_REDIRECT_URIS } from './redirect-uri-list'
import { entitlementState, listAllOwnedOAuthClients, SelfServiceClosedBlock, useEntitlements } from './shared'

type IssuedClient = { client: OwnedOAuthClient; secret: string | null }

function clientInputOf(client: OwnedOAuthClient, redirectUris: string[]): ClientInput {
  return {
    client_name: client.client_name,
    redirect_uris: redirectUris,
    scopes: client.scopes,
    logo_uri: client.logo_uri,
    client_uri: client.client_uri,
    description: client.description ?? null,
  }
}

export function IntegratePage() {
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [loading, setLoading] = useState(true)
  const [issued, setIssued] = useState<IssuedClient | null>(null)
  const [addingCallback, setAddingCallback] = useState(false)
  const issuer = useIssuer()
  const [message, setMessage] = useState('')
  const [rotatingClientIds, setRotatingClientIds] = useState<Set<string>>(() => new Set())
  const rotatingClientIdsRef = useRef(new Set<string>())
  const rotationIdempotencyKeysRef = useRef(new Map<string, string>())
  const [statusChangingClientIds, setStatusChangingClientIds] = useState<Set<string>>(() => new Set())
  const statusChangingClientIdsRef = useRef(new Set<string>())
  const [deletingClientIds, setDeletingClientIds] = useState<Set<string>>(() => new Set())
  const deletingClientIdsRef = useRef(new Set<string>())
  const loadRequestIdRef = useRef(0)
  const mountedRef = useRef(false)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<OwnedOAuthClient | null>(null)
  const entitlements = useEntitlements()
  const plans = entitlementState(entitlements)
  // plan === null 是唯一判据：平台未开放自助接入，创建入口关闭，已有应用照常管理
  const selfServiceClosed = plans.kind === 'closed'
  const gateNoteId = useId()
  const issuedOfficialUrl = issued ? officialCallbackUrl(issuer, issued.client.numeric_app_id) : null
  const issuedCallbackState: OfficialCallbackState = issued && issuedOfficialUrl !== null && issued.client.redirect_uris.includes(issuedOfficialUrl)
    ? 'present'
    : issued && issued.client.redirect_uris.length >= MAX_REDIRECT_URIS
      ? 'full'
      : 'absent'

  const load = useCallback(() => {
    if (!mountedRef.current) return
    const requestId = ++loadRequestIdRef.current
    setLoading(true)
    setMessage('')
    void listAllOwnedOAuthClients()
      .then((response) => {
        if (!mountedRef.current || requestId !== loadRequestIdRef.current) return
        setClients(response)
      })
      .catch((reason: unknown) => {
        if (!mountedRef.current || requestId !== loadRequestIdRef.current) return
        setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。')
      })
      .finally(() => {
        if (mountedRef.current && requestId === loadRequestIdRef.current) setLoading(false)
      })
  }, [])
  useEffect(() => {
    mountedRef.current = true
    load()
    return () => {
      mountedRef.current = false
      loadRequestIdRef.current += 1
    }
  }, [load])

  function closeDrawer() {
    setMessage('')
    setDrawerOpen(false)
  }

  function openCreate() {
    // 兜底：入口已是 aria-disabled，这里再拦一次，避免任何路径把用户送去吃 403
    if (selfServiceClosed) return
    setMessage('')
    setEditing(null)
    setDrawerOpen(true)
  }

  function openEdit(client: OwnedOAuthClient) {
    setMessage('')
    setEditing(client)
    setDrawerOpen(true)
  }

  function handleCreated(client: RegisteredOwnedOAuthClient) {
    const { client_secret, ...rest } = client
    setIssued({ client: rest, secret: client_secret ?? null })
    closeDrawer()
    load()
  }

  async function addOfficialCallback(url: string) {
    if (!issued || addingCallback) return
    const target = issued.client
    setAddingCallback(true)
    setMessage('')
    try {
      const redirectUris = [...target.redirect_uris, url]
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(target.client_id)}`, {
        method: 'PUT',
        body: JSON.stringify(clientInputOf(target, redirectUris)),
      })
      setIssued((current) => (current && current.client.client_id === target.client_id
        ? { ...current, client: { ...current.client, redirect_uris: redirectUris } }
        : current))
      load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '加入官方回调失败。')
    } finally {
      setAddingCallback(false)
    }
  }

  function handleUpdated() {
    closeDrawer()
    load()
  }

  async function rotate(client: OwnedOAuthClient) {
    const clientId = client.client_id
    if (rotatingClientIdsRef.current.has(clientId)) return
    if (!window.confirm('轮换后旧 Secret 将失效，且新 Secret 只显示这一次，继续吗？')) return
    rotatingClientIdsRef.current.add(clientId)
    setRotatingClientIds(new Set(rotatingClientIdsRef.current))
    setMessage('')
    try {
      const key = rotationIdempotencyKeysRef.current.get(clientId) ?? newIdempotencyKey()
      rotationIdempotencyKeysRef.current.set(clientId, key)
      const response = await apiFetch<{ client_id: string; client_secret: string }>(`/api/v1/auth/oauth-clients/${encodeURIComponent(clientId)}/rotate-secret`, {
        method: 'POST',
        headers: { 'Idempotency-Key': key },
      })
      rotationIdempotencyKeysRef.current.delete(clientId)
      setIssued({ client, secret: response.client_secret })
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Secret 轮换失败。')
    } finally {
      rotatingClientIdsRef.current.delete(clientId)
      setRotatingClientIds(new Set(rotatingClientIdsRef.current))
    }
  }

  async function setStatus(client: OwnedOAuthClient) {
    if (statusChangingClientIdsRef.current.has(client.client_id)) return
    const action = client.status === 'active' ? 'disable' : 'enable'
    const actionLabel = action === 'disable' ? '禁用' : '启用'
    const consequence = action === 'disable'
      ? '禁用后，该 OAuth 应用将无法发起新的授权，也无法获取新的令牌。'
      : '启用后，该 OAuth 应用可以重新发起授权并获取令牌。'
    if (!window.confirm(`确认${actionLabel}“${client.client_name}”吗？\n${consequence}`)) return
    statusChangingClientIdsRef.current.add(client.client_id)
    setStatusChangingClientIds(new Set(statusChangingClientIdsRef.current))
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client.client_id)}/${action}`, { method: 'POST' })
      load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '应用状态更新失败。')
    } finally {
      statusChangingClientIdsRef.current.delete(client.client_id)
      setStatusChangingClientIds(new Set(statusChangingClientIdsRef.current))
    }
  }

  async function remove(client: OwnedOAuthClient) {
    if (deletingClientIdsRef.current.has(client.client_id)) return
    if (!window.confirm(`确认删除“${client.client_name}”吗？\n删除后无法恢复：已签发的 Refresh Token 立即失效，占用的应用额度会被释放。数字 App ID 不会回收。`)) return
    deletingClientIdsRef.current.add(client.client_id)
    setDeletingClientIds(new Set(deletingClientIdsRef.current))
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client.client_id)}`, { method: 'DELETE' })
      load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '应用删除失败。')
    } finally {
      deletingClientIdsRef.current.delete(client.client_id)
      setDeletingClientIds(new Set(deletingClientIdsRef.current))
    }
  }

  return (
    <ConsoleLayout>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="chenxing-mono text-[11px] uppercase tracking-[0.28em] text-[var(--chenxing-cyan)]">// Developer</p>
          <h1 className="chenxing-h1 mt-2">接入应用</h1>
          <p className="chenxing-caption mt-2">
            {selfServiceClosed
              ? '平台未开放自助接入，暂不能注册新应用；已有应用仍可查看与管理'
              : '将「使用辰星通行证登录」接入你的应用，点击应用行查看配置与接入信息'}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <a href="https://wiki.auth.clya.top" className="chenxing-btn-ghost"><Icon name="book-open" size={16} />接入文档</a>
          {/* 禁用态用 aria-disabled 保留焦点，并用 aria-describedby 指向下方说明，
              让键盘和读屏用户拿到「为什么不能点」的原因，而不是只看到按钮变淡 */}
          <Button
            icon={selfServiceClosed ? 'lock-keyhole' : 'plus'}
            onClick={openCreate}
            aria-disabled={selfServiceClosed || undefined}
            aria-describedby={selfServiceClosed ? gateNoteId : undefined}
          >
            注册新应用
          </Button>
        </div>
      </div>

      {selfServiceClosed ? (
        <HudPanel as="section" className="mt-5" aria-labelledby={gateNoteId}>
          <SelfServiceClosedBlock>
            <span id={gateNoteId} className="chenxing-caption">
              「注册新应用」已停用：平台未开放自助接入，创建请求会被服务端拒绝。
            </span>
          </SelfServiceClosedBlock>
        </HudPanel>
      ) : null}

      {message && !drawerOpen ? <div className="mt-5"><Notice tone="warning">{message}</Notice></div> : null}
      {entitlements.error ? <div className="mt-5"><Notice tone="warning">{entitlements.error}<button className="chenxing-link ml-2" type="button" onClick={entitlements.retry}>重试</button></Notice></div> : null}
      {issued ? (
          <HudPanel className="mt-5">
            <div className="mb-4 flex items-center justify-between gap-4">
              <div>
                <h2 className="chenxing-h2">{issued.secret ? '一次性 Client Secret' : '公开客户端已创建'}</h2>
                <p className="chenxing-caption mt-1">
                  {issued.secret
                    ? '只保存在当前页面内存，刷新或离开页面后无法恢复。'
                    : '该应用类型不签发 Client Secret。令牌交换必须携带 PKCE code_verifier。'}
                </p>
              </div>
              <Icon name={issued.secret ? 'key-round' : 'shield-check'} className="text-[var(--chenxing-cyan)]" size={18} />
            </div>
            <div className={`grid gap-4 ${issued.secret ? 'md:grid-cols-2' : ''}`}>
              <div><span className="chenxing-label">Client ID</span><CopyValue value={issued.client.client_id} ariaLabel="复制 Client ID" /></div>
              {issued.secret ? (
                <div><span className="chenxing-label">Client Secret</span><CopyValue value={issued.secret} ariaLabel="复制 Client Secret" /></div>
              ) : null}
            </div>
            {issued.secret ? (
              <div className="mt-4"><Notice tone="warning">Secret 不会再次从列表接口返回，请立即保存到受保护的服务端配置中。</Notice></div>
            ) : (
              <div className="mt-4">
                <OfficialCallbackBlock
                  numericAppId={issued.client.numeric_app_id}
                  issuer={issuer}
                  state={issuedCallbackState}
                  busy={addingCallback}
                  onAdd={(url) => void addOfficialCallback(url)}
                />
              </div>
            )}
          </HudPanel>
        ) : null}

      <TablePanel
        className="mt-6"
        icon="boxes"
        title="我的接入应用"
        description={loading ? '加载中' : `${clients.length} 个应用`}
      >
        {!loading && !clients.length ? (
          <div className="mt-6">
            {selfServiceClosed ? (
              <EmptyState
                icon="lock-keyhole"
                title="暂无 OAuth 应用"
                description="平台未开放自助接入，当前不能自行创建应用。管理员为你分配套餐后即可在这里注册。"
              />
            ) : (
              <EmptyState icon="code-2" title="暂无 OAuth 项目" description="创建第一个项目后会显示在这里。" action={<Button className="mt-2" icon="plus" onClick={openCreate}>注册新应用</Button>} />
            )}
          </div>
        ) : (
          <DataTable
            minWidth={760}
            columns={['ID', '名称', '类型', '状态', { label: '操作', align: 'right' }]}
            empty={loading && !clients.length ? '正在加载接入应用。' : null}
          >
            {clients.map((client, index) => (
              <DataTableRow key={client.client_id} label={`编辑 ${client.client_name}`} onOpen={() => openEdit(client)}>
                <td className="chenxing-mono text-sm text-[var(--chenxing-muted-foreground)]">{String(index + 1).padStart(2, '0')}</td>
                <td className="min-w-0">
                  <p className="chenxing-body font-semibold leading-tight">{client.client_name}</p>
                  <p className="chenxing-mono break-all text-[11px] text-[var(--chenxing-muted-foreground)]">{client.client_id}</p>
                  <p className="chenxing-caption mt-1">{formatQuota(client)}</p>
                </td>
                <td><span className="chenxing-tag">{client.auth_method === 'none' ? '公开' : '机密'}</span></td>
                <td>
                  <span className={client.status === 'active' ? 'chenxing-tag-success' : 'chenxing-tag-warning'}>
                    {client.status === 'active' ? '已启用' : client.status}
                  </span>
                </td>
                <RowActions>
                  <RowAction
                    tone={client.status === 'active' ? 'danger' : 'default'}
                    disabled={statusChangingClientIds.has(client.client_id)}
                    onClick={() => void setStatus(client)}
                  >
                    {statusChangingClientIds.has(client.client_id)
                      ? `${client.status === 'active' ? '禁用' : '启用'}中…`
                      : client.status === 'active' ? '禁用' : '启用'}
                  </RowAction>
                  <RowAction onClick={() => openEdit(client)}>编辑</RowAction>
                  {client.auth_method === 'none' ? null : (
                    <RowAction disabled={rotatingClientIds.has(client.client_id)} onClick={() => void rotate(client)}>
                      {rotatingClientIds.has(client.client_id) ? '轮换中…' : '轮换'}
                    </RowAction>
                  )}
                  <RowAction tone="danger" disabled={deletingClientIds.has(client.client_id)} onClick={() => void remove(client)}>
                    {deletingClientIds.has(client.client_id) ? '删除中…' : '删除'}
                  </RowAction>
                </RowActions>
              </DataTableRow>
            ))}
          </DataTable>
        )}
        {issued?.secret || clients.some((client) => client.auth_method !== 'none') ? (
          <p className="chenxing-caption mt-4 flex items-center gap-2">
            <Icon name="shield-alert" className="shrink-0 text-[var(--chenxing-warning)]" size={16} />
            机密客户端的 Secret 只在创建或轮换时展示一次，遗失后只能重新生成。公开客户端没有 Secret。
          </p>
        ) : null}
      </TablePanel>

      <HudPanel as="section" className="mt-6">
        <h3 className="chenxing-h3 flex items-center gap-2"><Icon name="rocket" className="text-[var(--chenxing-cyan)]" size={18} />快速接入</h3>
        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          {[
            ['01', '注册应用', '创建应用并拿到 Client ID。机密客户端另发一次性 Secret；公开客户端用 PKCE，不签发 Secret。'],
            ['02', '配置回调地址', '第三方填自己的 HTTPS Redirect URI，并在自己域名发布 assetlinks.json。官方手机应用在编辑页一键加入本 Issuer 的官方回调，再由 Owner 在「软件链接」发布声明。'],
            ['03', '发起授权请求', '携带 PKCE 参数跳转授权端点，用授权码换取令牌。'],
          ].map(([n, title, copy]) => (
            <div className="flex gap-3" key={n}>
              <span className="chenxing-mono flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-[var(--chenxing-border-strong)] bg-[var(--chenxing-primary-soft)] text-sm text-[var(--chenxing-cyan)]">{n}</span>
              <div>
                <p className="chenxing-body font-semibold">{title}</p>
                <p className="chenxing-caption mt-0.5">{copy}</p>
              </div>
            </div>
          ))}
        </div>
      </HudPanel>

      {drawerOpen ? (
        <AppRegisterDrawer
          editing={editing}
          onClose={closeDrawer}
          onCreated={handleCreated}
          onUpdated={handleUpdated}
        />
      ) : null}
    </ConsoleLayout>
  )
}
