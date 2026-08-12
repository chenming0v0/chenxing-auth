import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import { apiFetch, type ClientInput, type OwnedOAuthClient, type RegisteredOwnedOAuthClient } from '../../api'
import { Drawer } from '../../components/drawer'
import { ConsoleLayout } from '../../components/shells'
import { Button, CopyValue, EmptyState, Field, HudPanel, Icon, Notice, TextAreaField } from '../../components/ui'
import { formatQuota, splitValues } from './developer-shared'
import { entitlementState, SelfServiceClosedBlock, useEntitlements } from './shared'

const REDIRECT_URI_RULE_MESSAGE = '仅允许 HTTPS；本地 HTTP 回调必须使用 127.0.0.1 或 [::1]，不接受 localhost、通配符与危险协议。'

// 前端镜像后端 src/clients/domain.rs::validate_redirect_uri 的规则集；前端只做即时反馈，服务端仍是权威校验。
function redirectUriProblem(value: string): string | null {
  if (value.includes('*')) return '不接受通配符'
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return '不是合法的 URL'
  }
  const { protocol, hostname, hash, username, password } = url
  if (protocol !== 'https:' && (protocol !== 'http:' || !isLoopbackHostname(hostname))) {
    return '仅允许 HTTPS，或 HTTP 回环地址（127.0.0.1 / [::1]）'
  }
  if (hash) return '不允许包含 fragment'
  if (username || password) return '不允许包含用户名或密码'
  return null
}

function isLoopbackHostname(hostname: string): boolean {
  // WHATWG URL 把 IPv6 host 序列化为带方括号形式，如 "[::1]"
  if (hostname === '[::1]') return true
  const octets = hostname.split('.')
  return octets.length === 4 && octets[0] === '127' && octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
}

function findInvalidRedirectUri(redirectUris: string[]): { value: string; reason: string } | null {
  for (const value of redirectUris) {
    const reason = redirectUriProblem(value)
    if (reason !== null) return { value, reason }
  }
  return null
}

export function IntegratePage() {
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [rotatingClientIds, setRotatingClientIds] = useState<Set<string>>(() => new Set())
  const rotatingClientIdsRef = useRef(new Set<string>())
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editing, setEditing] = useState<OwnedOAuthClient | null>(null)
  const [name, setName] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [scopes, setScopes] = useState('openid profile')
  const entitlements = useEntitlements()
  const plans = entitlementState(entitlements)
  // plan === null 是唯一判据：平台未开放自助接入，创建入口关闭，已有应用照常管理
  const selfServiceClosed = plans.kind === 'closed'
  const gateNoteId = useId()

  const load = () => {
    void apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients')
      .then((response) => setClients(response.items))
      .catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。'))
  }
  useEffect(() => { load() }, [])

  function closeDrawer() {
    setMessage('')
    setDrawerOpen(false)
  }

  function openCreate() {
    // 兜底：入口已是 aria-disabled，这里再拦一次，避免任何路径把用户送去吃 403
    if (selfServiceClosed) return
    setMessage('')
    setEditing(null)
    setName('')
    setRedirectUris('')
    setScopes('openid profile')
    setDrawerOpen(true)
  }

  function openEdit(client: OwnedOAuthClient) {
    setMessage('')
    setEditing(client)
    setName(client.client_name)
    setRedirectUris(client.redirect_uris.join('\n'))
    setScopes(client.scopes.join(' '))
    setDrawerOpen(true)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    const input: ClientInput = { client_name: name.trim(), redirect_uris: splitValues(redirectUris), scopes: splitValues(scopes) }
    if (!input.client_name || !input.redirect_uris.length || !input.scopes.length) {
      setMessage('请填写应用名称、至少一个 Redirect URI 和 Scope。')
      return
    }
    const invalid = findInvalidRedirectUri(input.redirect_uris)
    if (invalid) {
      setMessage(`「${invalid.value}」${invalid.reason}。${REDIRECT_URI_RULE_MESSAGE}`)
      return
    }
    setBusy(true)
    try {
      if (editing) {
        await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(editing.client_id)}`, {
          method: 'PUT', body: JSON.stringify(input),
        })
      } else {
        const response = await apiFetch<RegisteredOwnedOAuthClient>('/api/v1/auth/oauth-clients', {
          method: 'POST', body: JSON.stringify(input),
        })
        setSecret({ clientId: response.client_id, value: response.client_secret })
      }
      closeDrawer()
      load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '应用保存失败。')
    } finally {
      setBusy(false)
    }
  }

  async function rotate(clientId: string) {
    if (rotatingClientIdsRef.current.has(clientId)) return
    if (!window.confirm('轮换后旧 Secret 将失效，且新 Secret 只显示这一次，继续吗？')) return
    rotatingClientIdsRef.current.add(clientId)
    setRotatingClientIds(new Set(rotatingClientIdsRef.current))
    setMessage('')
    try {
      const response = await apiFetch<{ client_id: string; client_secret: string }>(`/api/v1/auth/oauth-clients/${encodeURIComponent(clientId)}/rotate-secret`, { method: 'POST' })
      setSecret({ clientId: response.client_id, value: response.client_secret })
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'Secret 轮换失败。')
    } finally {
      rotatingClientIdsRef.current.delete(clientId)
      setRotatingClientIds(new Set(rotatingClientIdsRef.current))
    }
  }

  async function setStatus(client: OwnedOAuthClient) {
    const action = client.status === 'active' ? 'disable' : 'enable'
    const actionLabel = action === 'disable' ? '禁用' : '启用'
    const consequence = action === 'disable'
      ? '禁用后，该 OAuth 应用将无法发起新的授权，也无法获取新的令牌。'
      : '启用后，该 OAuth 应用可以重新发起授权并获取令牌。'
    if (!window.confirm(`确认${actionLabel}“${client.client_name}”吗？\n${consequence}`)) return
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client.client_id)}/${action}`, { method: 'POST' })
      load()
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '应用状态更新失败。')
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
      {secret ? (
        <HudPanel className="mt-5">
          <div className="mb-4 flex items-center justify-between gap-4">
            <div>
              <h2 className="chenxing-h2">一次性 Client Secret</h2>
              <p className="chenxing-caption mt-1">只保存在当前页面内存，刷新或离开页面后无法恢复。</p>
            </div>
            <Icon name="key-round" className="text-[var(--chenxing-cyan)]" size={18} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <div><span className="chenxing-label">Client ID</span><CopyValue value={secret.clientId} ariaLabel="复制 Client ID" /></div>
            <div><span className="chenxing-label">Client Secret</span><CopyValue value={secret.value} ariaLabel="复制 Client Secret" /></div>
          </div>
          <div className="mt-4"><Notice tone="warning">Secret 不会再次从列表接口返回，请立即保存到受保护的服务端配置中。</Notice></div>
        </HudPanel>
      ) : null}

      <HudPanel as="section" className="mt-6">
        <div className="flex items-center justify-between gap-4">
          <h2 className="chenxing-h2 flex items-center gap-3">我的接入应用<span className="chenxing-chip">{clients.length} 个应用</span></h2>
        </div>
        <div className="chenxing-app-grid mt-5 hidden px-4 pb-2 lg:grid">
          <span className="chenxing-label !mb-0">ID</span>
          <span className="chenxing-label !mb-0">名称</span>
          <span className="chenxing-label !mb-0">分组</span>
          <span className="chenxing-label !mb-0">状态</span>
          <span className="chenxing-label !mb-0 text-right">操作</span>
        </div>
        {clients.map((client, index) => (
          <article key={client.client_id} className="chenxing-app-grid chenxing-app-row mt-2 lg:mt-0" onClick={() => openEdit(client)}>
            <span className="chenxing-mono text-sm text-[var(--chenxing-muted-foreground)]">{String(index + 1).padStart(2, '0')}</span>
            <div className="min-w-0">
              <p className="chenxing-body truncate font-semibold leading-tight">{client.client_name}</p>
              <p className="chenxing-mono truncate text-[11px] text-[var(--chenxing-muted-foreground)]">{client.client_id}</p>
              <p className="chenxing-caption mt-1 hidden sm:block">{formatQuota(client)}</p>
            </div>
            <span className="chenxing-tag hidden lg:inline-flex">default</span>
            <span className={`${client.status === 'active' ? 'chenxing-tag-success' : 'chenxing-tag-warning'} hidden lg:inline-flex`}>
              {client.status === 'active' ? '已启用' : client.status}
            </span>
            <div className="flex items-center justify-end gap-2" onClick={(event) => event.stopPropagation()}>
              <Button
                variant={client.status === 'active' ? 'danger' : 'ghost'}
                icon="power"
                onClick={() => void setStatus(client)}
              >
                {client.status === 'active' ? '禁用' : '启用'}
              </Button>
              <Button variant="ghost" icon="pencil" onClick={() => openEdit(client)}>编辑</Button>
              <Button variant="ghost" icon="refresh-cw" disabled={rotatingClientIds.has(client.client_id)} onClick={() => void rotate(client.client_id)}>
                {rotatingClientIds.has(client.client_id) ? '轮换中…' : '轮换'}
              </Button>
            </div>
          </article>
        ))}
        {!clients.length ? (
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
        ) : null}
        <p className="chenxing-caption mt-4 flex items-center gap-2">
          <Icon name="shield-alert" className="shrink-0 text-[var(--chenxing-warning)]" size={16} />
          Client Secret 仅在创建应用时展示一次，遗失后只能重新生成。
        </p>
      </HudPanel>

      <HudPanel as="section" className="mt-6">
        <h3 className="chenxing-h3 flex items-center gap-2"><Icon name="rocket" className="text-[var(--chenxing-cyan)]" size={18} />快速接入</h3>
        <div className="mt-5 grid gap-4 lg:grid-cols-3">
          {[
            ['01', '注册应用', '创建应用，获取 Client ID 与仅展示一次的 Client Secret。'],
            ['02', '配置回调地址', '登记 Redirect URI，辰星仅向精确匹配的地址回跳授权码。'],
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
        <Drawer
          title={editing ? '编辑应用' : '注册新应用'}
          description="服务端负责校验 Redirect URI、Scope 和配额。"
          onClose={closeDrawer}
          onSubmit={save}
          busy={busy}
          footer={
            <>
              <Button type="button" variant="ghost" onClick={closeDrawer} disabled={busy}>取消</Button>
              <Button type="submit" icon="save" disabled={busy}>{busy ? '保存中…' : editing ? '保存更新' : '创建应用'}</Button>
            </>
          }
        >
          {message ? <Notice tone="warning">{message}</Notice> : null}
          <HudPanel className="space-y-4 !p-5">
            <Field label="应用名称" placeholder="例如：星尘控制台" value={name} onChange={(event) => setName(event.target.value)} required />
            <TextAreaField label="Redirect URI" placeholder="每行一个严格匹配的 URI" value={redirectUris} onChange={(event) => setRedirectUris(event.target.value)} required hint={REDIRECT_URI_RULE_MESSAGE} />
            <TextAreaField label="Scope" value={scopes} onChange={(event) => setScopes(event.target.value)} required hint="用空格、逗号或换行分隔。" />
          </HudPanel>
        </Drawer>
      ) : null}
    </ConsoleLayout>
  )
}
