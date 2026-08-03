import { useEffect, useState, type FormEvent } from 'react'
import { Check, Code2, FlaskConical, Globe2, KeyRound, ShieldCheck } from 'lucide-react'
import { apiFetch, type ClientInput, type OwnedOAuthClient, type RegisteredOwnedOAuthClient } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, CopyValue, Field, HudPanel, Notice, PageHeader } from '../../components/ui'

function splitValues(value: string): string[] {
  return value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
}

function formatQuota(client: OwnedOAuthClient): string {
  return `今日 ${client.quota.daily_used} / ${client.quota.daily_limit} · 本月 ${client.quota.monthly_used} / ${client.quota.monthly_limit}`
}

export function IntegratePage() {
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null)
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [redirectUris, setRedirectUris] = useState('')
  const [scopes, setScopes] = useState('openid profile')

  const load = () => { void apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients').then((response) => setClients(response.items)).catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。')) }
  useEffect(() => { load() }, [])

  async function create(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    const input: ClientInput = { client_name: name.trim(), redirect_uris: splitValues(redirectUris), scopes: splitValues(scopes) }
    if (!input.client_name || !input.redirect_uris.length || !input.scopes.length) { setMessage('请填写应用名称、至少一个 Redirect URI 和 Scope。'); return }
    setBusy(true)
    try {
      const response = await apiFetch<RegisteredOwnedOAuthClient>('/api/v1/auth/oauth-clients', { method: 'POST', body: JSON.stringify(input) })
      setSecret({ clientId: response.client_id, value: response.client_secret })
      setName(''); setRedirectUris(''); setScopes('openid profile')
      load()
    } catch (error) { setMessage(error instanceof Error ? error.message : '应用创建失败。') }
    finally { setBusy(false) }
  }

  async function rotate(clientId: string) {
    if (!window.confirm('轮换后旧 Secret 将失效，且新 Secret 只显示这一次，继续吗？')) return
    setMessage('')
    try {
      const response = await apiFetch<{ client_id: string; client_secret: string }>(`/api/v1/auth/oauth-clients/${encodeURIComponent(clientId)}/rotate-secret`, { method: 'POST' })
      setSecret({ clientId: response.client_id, value: response.client_secret })
    } catch (error) { setMessage(error instanceof Error ? error.message : 'Secret 轮换失败。') }
  }

  async function setStatus(client: OwnedOAuthClient) {
    const next = client.status === 'active' ? '禁用' : '启用'
    if (!window.confirm(`确认${next}“${client.client_name}”吗？`)) return
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client.client_id)}/${client.status === 'active' ? 'disable' : 'enable'}`, { method: 'POST' })
      load()
    } catch (error) { setMessage(error instanceof Error ? error.message : '应用状态更新失败。') }
  }

  return <ConsoleLayout><PageHeader eyebrow="DEVELOPER / INTEGRATE" title="接入应用" description="创建和管理当前账号拥有的 OAuth 项目。服务端负责校验 Redirect URI、Scope 和配额。" action={<Badge><Code2 size={13} />OAuth 2.0 / OIDC</Badge>} />{message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}{secret && <HudPanel><div className="panel-heading"><div><h2>一次性 Client Secret</h2><p>只保存在当前页面内存，刷新或离开页面后无法恢复。</p></div><KeyRound size={18} color="var(--chenxing-cyan)" /></div><div className="content-grid"><div><span className="chenxing-label">Client ID</span><CopyValue value={secret.clientId} /></div><div><span className="chenxing-label">Client Secret</span><CopyValue value={secret.value} /></div></div><Notice tone="warning">Secret 不会再次从列表接口返回，请立即保存到受保护的服务端配置中。</Notice></HudPanel>}<div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>创建 OAuth 应用</h2><p>创建成功后 Secret 只返回一次。</p></div><Globe2 size={18} color="var(--chenxing-cyan)" /></div><form className="auth-form" onSubmit={create}><Field label="应用名称" placeholder="例如：我的业务应用" value={name} onChange={(event) => setName(event.target.value)} required /><label className="field"><span className="chenxing-label">Redirect URI</span><textarea placeholder="每行一个严格匹配的 URI" value={redirectUris} onChange={(event) => setRedirectUris(event.target.value)} required /><small className="field-hint">服务端会严格校验 URI，不使用通配符。</small></label><label className="field"><span className="chenxing-label">Scope</span><textarea value={scopes} onChange={(event) => setScopes(event.target.value)} required /><small className="field-hint">用空格、逗号或换行分隔。</small></label><Button type="submit" icon="rocket" disabled={busy}>{busy ? '创建中…' : '创建 OAuth 应用'}</Button></form></HudPanel><HudPanel><div className="panel-heading"><div><h2>接入检查清单</h2><p>上线前确认协议边界。</p></div><ShieldCheck size={18} color="var(--chenxing-cyan)" /></div><div className="checklist"><div><Check size={15} /><span><strong>严格匹配 Redirect URI</strong><small>客户端不放宽服务端校验规则。</small></span></div><div><Check size={15} /><span><strong>启用 PKCE</strong><small>浏览器和移动端绑定 verifier。</small></span></div><div><Check size={15} /><span><strong>只申请必要 Scope</strong><small>从服务端允许的范围开始。</small></span></div><div><Check size={15} /><span><strong>保护 Client Secret</strong><small>不要放入浏览器或普通日志。</small></span></div></div></HudPanel></div><HudPanel className="integrated-list"><div className="panel-heading"><div><h2>你的应用</h2><p>{clients.length} 个服务端项目</p></div></div>{clients.length ? <div className="list-stack">{clients.map((client) => <ClientRow key={client.client_id} client={client} onReload={load} onRotate={() => void rotate(client.client_id)} onToggle={() => void setStatus(client)} onMessage={setMessage} />)}</div> : <div className="empty-state"><Code2 size={24} /><strong>暂无 OAuth 项目</strong><span>创建第一个项目后会显示在这里。</span></div>}</HudPanel></ConsoleLayout>
}

function ClientRow({ client, onReload, onRotate, onToggle, onMessage }: { client: OwnedOAuthClient; onReload: () => void; onRotate: () => void; onToggle: () => void; onMessage: (message: string) => void }) {
  const [editing, setEditing] = useState(false)
  const [name, setName] = useState(client.client_name)
  const [redirectUris, setRedirectUris] = useState(client.redirect_uris.join('\n'))
  const [scopes, setScopes] = useState(client.scopes.join(' '))
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    if (editing) return
    setName(client.client_name)
    setRedirectUris(client.redirect_uris.join('\n'))
    setScopes(client.scopes.join(' '))
  }, [client, editing])
  async function update(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    onMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client.client_id)}`, { method: 'PUT', body: JSON.stringify({ client_name: name.trim(), redirect_uris: splitValues(redirectUris), scopes: splitValues(scopes) }) })
      setEditing(false); onReload()
    } catch (error) { onMessage(error instanceof Error ? error.message : '应用更新失败。') }
    finally { setBusy(false) }
  }
  return <div className="list-row app-list-row"><div className="app-list-main"><span className="app-mark"><Code2 size={19} /></span><span><strong>{client.client_name}</strong><small className="code-text">{client.client_id}</small><small>{client.redirect_uris.join(' · ')}</small><small className="code-text">{client.scopes.join(' · ')} · {formatQuota(client)}</small></span></div><div className="panel-actions"><Badge tone={client.status === 'active' ? 'success' : 'warning'}>{client.status}</Badge><Button variant="ghost" icon="settings" onClick={() => setEditing(!editing)} aria-label={`编辑 ${client.client_name}`}>编辑</Button><Button variant="ghost" icon={client.status === 'active' ? 'x' : 'check'} onClick={onToggle}>{client.status === 'active' ? '禁用' : '启用'}</Button><Button variant="danger" icon="refresh-cw" onClick={onRotate}>轮换 Secret</Button></div>{editing && <form className="auth-form" onSubmit={update}><Field label="应用名称" value={name} onChange={(event) => setName(event.target.value)} /><label className="field"><span className="chenxing-label">Redirect URI</span><textarea value={redirectUris} onChange={(event) => setRedirectUris(event.target.value)} /></label><label className="field"><span className="chenxing-label">Scope</span><textarea value={scopes} onChange={(event) => setScopes(event.target.value)} /></label><Button type="submit" icon="save" disabled={busy}>保存更新</Button></form>}</div>
}

export function PlaygroundPage() {
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [selectedId, setSelectedId] = useState('')
  const [redirectUri, setRedirectUri] = useState('')
  const [scope, setScope] = useState('openid')
  const [result, setResult] = useState<{ url: string; verifier: string; state: string } | null>(null)
  const [message, setMessage] = useState('')
  useEffect(() => { void apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients').then((response) => { setClients(response.items); const first = response.items[0]; if (first) { setSelectedId(first.client_id); setRedirectUri(first.redirect_uris[0] || ''); setScope(first.scopes.join(' ')) } }).catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。')) }, [])
  function selectClient(clientId: string) { const client = clients.find((item) => item.client_id === clientId); setSelectedId(clientId); setRedirectUri(client?.redirect_uris[0] || ''); setScope(client?.scopes.join(' ') || 'openid') }
  async function submit(event: FormEvent) {
    event.preventDefault()
    const client = clients.find((item) => item.client_id === selectedId)
    if (!client || !redirectUri || !scope.trim()) { setMessage('请选择应用并填写服务端允许的 Redirect URI 和 Scope。'); return }
    try {
      const random = (size: number) => { const bytes = new Uint8Array(size); crypto.getRandomValues(bytes); return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('') }
      const verifier = random(32)
      const state = random(16)
      const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
      const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
      const url = new URL('/oauth/authorize', window.location.origin)
      url.searchParams.set('client_id', client.client_id); url.searchParams.set('redirect_uri', redirectUri); url.searchParams.set('response_type', 'code'); url.searchParams.set('scope', scope.trim()); url.searchParams.set('state', state); url.searchParams.set('code_challenge', challenge); url.searchParams.set('code_challenge_method', 'S256')
      setResult({ url: url.toString(), verifier, state }); setMessage('')
    } catch { setMessage('无法生成 PKCE 参数，请检查浏览器加密能力。') }
  }
  return <ConsoleLayout><PageHeader eyebrow="DEVELOPER / PLAYGROUND" title="授权测试" description="根据当前账号拥有的 OAuth 项目生成 Authorization Code + PKCE 请求参数。此页面不会交换或保存 Token。" action={<Badge tone="warning"><FlaskConical size={13} />测试工具</Badge>} />{message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}<div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>生成测试请求</h2><p>参数只保留在当前页面内存。</p></div><KeyRound size={18} color="var(--chenxing-cyan)" /></div><form className="auth-form" onSubmit={submit}><label className="field"><span className="chenxing-label">客户端</span><select value={selectedId} onChange={(event) => selectClient(event.target.value)}><option value="">请选择服务端项目</option>{clients.map((client) => <option key={client.client_id} value={client.client_id}>{client.client_name} · {client.client_id}</option>)}</select></label><Field label="Redirect URI" value={redirectUri} onChange={(event) => setRedirectUri(event.target.value)} /><Field label="Scope" value={scope} onChange={(event) => setScope(event.target.value)} hint="必须是客户端已配置的 Scope。" /><Button type="submit" icon="send" disabled={!clients.length}>生成授权 URL</Button></form></HudPanel><HudPanel><div className="panel-heading"><div><h2>当前流程</h2><p>标准 Authorization Code 流程</p></div><span className="chenxing-chip">PKCE S256</span></div><div className="flow-steps"><div className="flow-step is-done"><span>01</span><div><strong>生成 state / verifier</strong><small>只保留在当前页面内存。</small></div></div><div className="flow-step is-done"><span>02</span><div><strong>打开授权端点</strong><small>由后端校验 client、redirect 和请求参数。</small></div></div><div className="flow-step"><span>03</span><div><strong>交换授权码</strong><small>由你的后端使用 verifier 换取 Token。</small></div></div></div></HudPanel></div>{result && <HudPanel className="playground-result"><div className="panel-heading"><div><h2>授权 URL 已生成</h2><p>请在独立窗口打开；不要把 verifier 放入日志。</p></div><Badge tone="success"><Check size={13} />READY</Badge></div><CopyValue value={result.url} /><div className="content-grid grid-2"><div><span className="chenxing-label">State</span><CopyValue value={result.state} /></div><div><span className="chenxing-label">Code Verifier</span><CopyValue value={result.verifier} /></div></div></HudPanel>}</ConsoleLayout>
}
