import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Activity, Database, Gauge, KeyRound, Server, ShieldCheck, Users } from 'lucide-react'
import { useLocation, useNavigate } from '../router'
import { apiFetch, type AdminMeResponse, type AdminOverview, type AuditEvent, type ClientSummary, type KeyRotationResponse, type Paged, type PublicUser, type RegistrationEmailSetting } from '../api'
import { ConsoleLayout } from '../components/shells'
import { Badge, Button, Field, HudPanel, Notice, PageHeader } from '../components/ui'

type AdminAccess = { data: AdminMeResponse | null; loading: boolean; error: string }

function useAdminAccess(): AdminAccess {
  const [data, setData] = useState<AdminMeResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let active = true
    void apiFetch<AdminMeResponse>('/api/v1/admin/auth/me').then((value) => { if (active) setData(value) }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '管理身份加载失败。') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])
  return { data, error, loading }
}

function AdminGate({ access, permission, children }: { access: AdminAccess; permission?: string; children: ReactNode }) {
  if (access.loading) return <HudPanel><Notice>正在检查管理身份和权限。</Notice></HudPanel>
  if (access.error || !access.data) return <HudPanel><Notice tone="warning">{access.error || '当前会话不是有效的管理员会话。'}</Notice></HudPanel>
  if (permission && !access.data.permissions.includes(permission)) return <HudPanel><Notice tone="warning">当前管理身份没有 `{permission}` 权限，服务端数据不会在此页面展示。</Notice></HudPanel>
  return <>{children}</>
}

function formatDate(value?: string): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
}

export function AdminDashboard() {
  const access = useAdminAccess()
  const [overview, setOverview] = useState<AdminOverview | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    if (!access.data?.permissions.includes('manage_clients')) return
    let active = true
    void apiFetch<AdminOverview>('/api/v1/admin/overview').then((value) => { if (active) setOverview(value) }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '概览数据加载失败。') })
    return () => { active = false }
  }, [access.data])
  return <ConsoleLayout><PageHeader eyebrow="ADMIN / DASHBOARD" title="系统仪表盘" description="只显示管理 API 返回的资源统计和当前权限状态。" action={<Badge tone="success"><span className="chenxing-status-dot" />权限已校验</Badge>} /><AdminGate access={access} permission="manage_clients">{error && <div className="auth-feedback"><Notice tone="warning">{error}</Notice></div>}{overview && <><div className="stat-grid"><HudPanel className="stat-panel"><header><span>注册用户</span><Users className="stat-icon" size={19} /></header><h2>{overview.users}</h2><footer><span>服务端总数</span><Badge tone="success">LIVE</Badge></footer></HudPanel><HudPanel className="stat-panel"><header><span>OAuth 客户端</span><KeyRound className="stat-icon" size={19} /></header><h2>{overview.oauth_clients}</h2><footer><span>服务端总数</span><Badge tone="success">LIVE</Badge></footer></HudPanel><HudPanel className="stat-panel"><header><span>审计事件</span><Activity className="stat-icon" size={19} /></header><h2>{overview.audit_events}</h2><footer><span>管理员 {overview.administrators}</span><Badge>LIVE</Badge></footer></HudPanel></div><div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>管理权限</h2><p>每项操作仍由服务端再次校验。</p></div><ShieldCheck size={18} color="var(--chenxing-cyan)" /></div><div className="list-stack">{access.data?.permissions.map((permission) => <div className="list-row" key={permission}><strong>{permission}</strong><Badge tone="success">允许</Badge></div>)}</div></HudPanel><HudPanel><div className="panel-heading"><div><h2>数据来源</h2><p>本页不使用前端统计常量。</p></div><Gauge size={18} color="var(--chenxing-cyan)" /></div><Notice tone="info">概览、用户、Client 和审计页面均从对应 API 读取；受限响应不会保留半更新数据。</Notice></HudPanel></div></>}</AdminGate></ConsoleLayout>
}

export function AdminUsers() {
  const access = useAdminAccess()
  return <ConsoleLayout><PageHeader eyebrow="ADMIN / USERS" title="用户管理" description="服务端分页查询用户，并按 AdminPermission 控制状态和角色操作。" /><AdminGate access={access} permission="manage_users"><UsersTable access={access} /></AdminGate></ConsoleLayout>
}

function UsersTable({ access }: { access: AdminAccess }) {
  const location = useLocation()
  const navigate = useNavigate()
  const params = new URLSearchParams(location.search)
  const [search, setSearch] = useState(params.get('search') || '')
  const [status, setStatus] = useState(params.get('status') || '')
  const [page, setPage] = useState(Number(params.get('page') || 1))
  const [result, setResult] = useState<Paged<PublicUser> | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState<number | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const pageSize = 20
  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setSearch(current.get('search') || '')
    setStatus(current.get('status') || '')
    setPage(Number(current.get('page') || 1))
  }, [location.search])
  const updateQuery = (nextPage = page) => { const next = new URLSearchParams(); if (search) next.set('search', search); if (status) next.set('status', status); next.set('page', String(nextPage)); navigate(`/admin/users?${next.toString()}`) }
  useEffect(() => {
    const currentPage = Number(new URLSearchParams(location.search).get('page') || 1)
    if (currentPage !== page) { setPage(currentPage); return }
    let active = true
    const current = new URLSearchParams(location.search)
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) }); if (current.get('search')) query.set('search', current.get('search') as string); if (current.get('status')) query.set('status', current.get('status') as string)
    void apiFetch<Paged<PublicUser>>(`/api/v1/admin/users/query?${query}`).then((value) => { if (active) setResult(value) }).catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '用户查询失败。') } })
    return () => { active = false }
  }, [location.search, page, refreshKey])
  async function setUserStatus(user: PublicUser) {
    if (!access.data?.permissions.includes('manage_users')) return
    const nextStatus = user.status === 'disabled' ? 'active' : 'disabled'
    if (!window.confirm(`确认将 ${user.display_name || user.username} 设为 ${nextStatus} 吗？`)) return
    setBusy(user.id); setError('')
    try { await apiFetch<void>(`/api/v1/admin/users/${user.id}/${nextStatus}`, { method: 'POST' }); setRefreshKey((value) => value + 1) } catch (reason) { setError(reason instanceof Error ? reason.message : '用户状态更新失败。') } finally { setBusy(null) }
  }
  async function setRole(user: PublicUser, role: string) {
    if (!access.data?.permissions.includes('manage_roles') || role === user.role) return
    setBusy(user.id); setError('')
    try { await apiFetch<void>(`/api/v1/admin/users/${user.id}/role`, { method: 'POST', body: JSON.stringify({ role }) }); setRefreshKey((value) => value + 1) } catch (reason) { setError(reason instanceof Error ? reason.message : '用户角色更新失败。') } finally { setBusy(null) }
  }
  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  return <HudPanel>{error && <div className="auth-feedback"><Notice tone="warning">{error}</Notice></div>}<div className="panel-heading"><div><h2>用户目录</h2><p>服务端返回 {result?.total ?? '—'} 条记录</p></div><div className="table-toolbar"><input className="search-input" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索用户名或邮箱" /><select className="search-input" value={status} onChange={(event) => setStatus(event.target.value)}><option value="">全部状态</option><option value="active">active</option><option value="disabled">disabled</option></select><Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button></div></div><div className="table-wrap"><table className="data-table"><thead><tr><th>用户</th><th>角色</th><th>状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody>{result?.items.map((user) => <tr key={user.id}><td><div className="table-person"><span className="avatar-button">{(user.display_name || user.username).slice(0, 1)}</span><span><strong>{user.display_name || user.username}</strong><small>{user.email}</small></span></div></td><td><select value={user.role} disabled={!access.data?.permissions.includes('manage_roles') || busy === user.id} onChange={(event) => void setRole(user, event.target.value)}><option value="user">user</option><option value="admin">admin</option><option value="owner">owner</option></select></td><td><Badge tone={user.status === 'active' ? 'success' : 'warning'}>{user.status}</Badge></td><td>{formatDate(user.created_at)}</td><td><Button variant={user.status === 'active' ? 'danger' : 'ghost'} icon={user.status === 'active' ? 'x' : 'check'} disabled={!access.data?.permissions.includes('manage_users') || busy === user.id} onClick={() => void setUserStatus(user)}>{user.status === 'active' ? '禁用' : '启用'}</Button></td></tr>)}</tbody></table></div>{!result?.items.length && <div className="empty-state"><Users size={24} /><strong>{result ? '没有匹配用户' : '正在加载用户'}</strong></div>}<div className="panel-actions"><Button variant="ghost" icon="arrow-right" disabled={page <= 1} onClick={() => updateQuery(page - 1)} aria-label="上一页">上一页</Button><span className="field-hint">第 {page} / {totalPages} 页</span><Button variant="ghost" icon="arrow-right" disabled={page >= totalPages} onClick={() => updateQuery(page + 1)} aria-label="下一页">下一页</Button></div></HudPanel>
}

export function AdminClients() {
  const access = useAdminAccess()
  return <ConsoleLayout><PageHeader eyebrow="ADMIN / CLIENTS" title="OAuth 客户端" description="服务端分页查询全局 Client，不展示 Secret 或 Secret 哈希。" /><AdminGate access={access} permission="manage_clients"><ClientsTable access={access} /></AdminGate></ConsoleLayout>
}

function ClientsTable({ access }: { access: AdminAccess }) {
  const location = useLocation(); const navigate = useNavigate(); const params = new URLSearchParams(location.search)
  const [search, setSearch] = useState(params.get('search') || ''); const [status, setStatus] = useState(params.get('status') || ''); const [page, setPage] = useState(Number(params.get('page') || 1)); const [result, setResult] = useState<Paged<ClientSummary> | null>(null); const [error, setError] = useState(''); const [refreshKey, setRefreshKey] = useState(0)
  const pageSize = 20
  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setSearch(current.get('search') || '')
    setStatus(current.get('status') || '')
    setPage(Number(current.get('page') || 1))
  }, [location.search])
  const updateQuery = (nextPage = page) => { const next = new URLSearchParams(); if (search) next.set('search', search); if (status) next.set('status', status); next.set('page', String(nextPage)); navigate(`/admin/clients?${next.toString()}`) }
  useEffect(() => { const current = new URLSearchParams(location.search); const currentPage = Number(current.get('page') || 1); if (currentPage !== page) { setPage(currentPage); return }; const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) }); if (current.get('search')) query.set('search', current.get('search') as string); if (current.get('status')) query.set('status', current.get('status') as string); let active = true; void apiFetch<Paged<ClientSummary>>(`/api/v1/admin/clients/query?${query}`).then((value) => { if (active) setResult(value) }).catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : 'Client 查询失败。') } }); return () => { active = false } }, [location.search, page, refreshKey])
  async function setClientStatus(client: ClientSummary) { if (!access.data?.permissions.includes('manage_clients')) return; const action = client.status === 'active' ? 'disable' : 'enable'; if (!window.confirm(`确认${action === 'disable' ? '禁用' : '启用'} ${client.client_name} 吗？`)) return; try { await apiFetch<void>(`/api/v1/admin/clients/${encodeURIComponent(client.client_id)}/${action}`, { method: 'POST' }); setRefreshKey((value) => value + 1) } catch (reason) { setError(reason instanceof Error ? reason.message : 'Client 状态更新失败。') } }
  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  return <HudPanel>{error && <div className="auth-feedback"><Notice tone="warning">{error}</Notice></div>}<div className="panel-heading"><div><h2>Client 目录</h2><p>服务端返回 {result?.total ?? '—'} 条记录</p></div><div className="table-toolbar"><input className="search-input" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索 Client 或名称" /><Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button></div></div><div className="table-wrap"><table className="data-table"><thead><tr><th>Client</th><th>Owner</th><th>Redirect URI</th><th>状态</th><th>操作</th></tr></thead><tbody>{result?.items.map((client) => <tr key={client.client_id}><td><strong>{client.client_name}</strong><small className="code-text">{client.client_id}</small></td><td>{client.owner_user_id ?? '—'}</td><td><small>{client.redirect_uris.join(' · ')}</small></td><td><Badge tone={client.status === 'active' ? 'success' : 'warning'}>{client.status}</Badge></td><td><Button variant={client.status === 'active' ? 'danger' : 'ghost'} icon={client.status === 'active' ? 'x' : 'check'} onClick={() => void setClientStatus(client)}>{client.status === 'active' ? '禁用' : '启用'}</Button></td></tr>)}</tbody></table></div>{!result?.items.length && <div className="empty-state"><KeyRound size={24} /><strong>{result ? '没有匹配 Client' : '正在加载 Client'}</strong></div>}<div className="panel-actions"><Button variant="ghost" icon="arrow-right" disabled={page <= 1} onClick={() => updateQuery(page - 1)}>上一页</Button><span className="field-hint">第 {page} / {totalPages} 页</span><Button variant="ghost" icon="arrow-right" disabled={page >= totalPages} onClick={() => updateQuery(page + 1)}>下一页</Button></div></HudPanel>
}

export function AdminAudit() {
  const access = useAdminAccess()
  return <ConsoleLayout><PageHeader eyebrow="ADMIN / AUDIT" title="审计事件" description="按服务端分页查询安全事件，只展示非敏感索引字段。" /><AdminGate access={access} permission="read_audit"><AuditTable /></AdminGate></ConsoleLayout>
}

function AuditTable() {
  const location = useLocation(); const navigate = useNavigate(); const params = new URLSearchParams(location.search)
  const [action, setAction] = useState(params.get('action') || ''); const [resourceType, setResourceType] = useState(params.get('resource_type') || ''); const [page, setPage] = useState(Number(params.get('page') || 1)); const [result, setResult] = useState<Paged<AuditEvent> | null>(null); const [error, setError] = useState('')
  const pageSize = 20; const updateQuery = (nextPage = page) => { const next = new URLSearchParams(); if (action) next.set('action', action); if (resourceType) next.set('resource_type', resourceType); next.set('page', String(nextPage)); navigate(`/admin/audit?${next.toString()}`) }
  useEffect(() => { const current = new URLSearchParams(location.search); setAction(current.get('action') || ''); setResourceType(current.get('resource_type') || ''); setPage(Number(current.get('page') || 1)) }, [location.search])
  useEffect(() => { const current = new URLSearchParams(location.search); const currentPage = Number(current.get('page') || 1); if (currentPage !== page) { setPage(currentPage); return }; const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) }); if (current.get('action')) query.set('action', current.get('action') as string); if (current.get('resource_type')) query.set('resource_type', current.get('resource_type') as string); let active = true; void apiFetch<Paged<AuditEvent>>(`/api/v1/admin/audit/query?${query}`).then((value) => { if (active) setResult(value) }).catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '审计查询失败。') } }); return () => { active = false } }, [location.search, page])
  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  return <HudPanel>{error && <div className="auth-feedback"><Notice tone="warning">{error}</Notice></div>}<div className="panel-heading"><div><h2>审计目录</h2><p>服务端返回 {result?.total ?? '—'} 条记录</p></div><div className="table-toolbar"><input className="search-input" value={action} onChange={(event) => setAction(event.target.value)} placeholder="action" /><input className="search-input" value={resourceType} onChange={(event) => setResourceType(event.target.value)} placeholder="resource_type" /><Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button></div></div><div className="table-wrap"><table className="data-table"><thead><tr><th>时间</th><th>动作</th><th>资源</th><th>执行者</th></tr></thead><tbody>{result?.items.map((event, index) => <tr key={event.id ?? `${event.created_at}-${index}`}><td>{formatDate(event.created_at)}</td><td className="code-text">{event.action || '—'}</td><td>{event.resource_type || '—'}{event.resource_id && <small>{event.resource_id}</small>}</td><td>{event.actor_type || '—'}{event.actor_id && <small>{event.actor_id}</small>}</td></tr>)}</tbody></table></div>{!result?.items.length && <div className="empty-state"><Activity size={24} /><strong>{result ? '暂无审计事件' : '正在加载审计事件'}</strong></div>}<div className="panel-actions"><Button variant="ghost" icon="arrow-right" disabled={page <= 1} onClick={() => updateQuery(page - 1)}>上一页</Button><span className="field-hint">第 {page} / {totalPages} 页</span><Button variant="ghost" icon="arrow-right" disabled={page >= totalPages} onClick={() => updateQuery(page + 1)}>下一页</Button></div></HudPanel>
}

export function AdminSettings() {
  const access = useAdminAccess()
  return <ConsoleLayout><PageHeader eyebrow="SYSTEM / SETTINGS" title="系统设置" description="管理 API 当前提供注册发件地址和签名密钥轮换操作。" action={<Badge><Server size={13} />CONFIGURATION</Badge>} /><AdminGate access={access} permission="manage_settings"><SettingsPanel access={access} /></AdminGate></ConsoleLayout>
}

function SettingsPanel({ access }: { access: AdminAccess }) {
  const [setting, setSetting] = useState<RegistrationEmailSetting | null>(null); const [email, setEmail] = useState(''); const [message, setMessage] = useState(''); const [keyResult, setKeyResult] = useState<KeyRotationResponse | null>(null); const [busy, setBusy] = useState(false)
  useEffect(() => { void apiFetch<RegistrationEmailSetting>('/api/v1/admin/settings/registration-email').then((value) => { setSetting(value); setEmail(value.registration_email_from || '') }).catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '系统设置加载失败。')) }, [])
  async function save(event: FormEvent) { event.preventDefault(); setMessage(''); setBusy(true); try { const value = await apiFetch<RegistrationEmailSetting>('/api/v1/admin/settings/registration-email', { method: 'PUT', body: JSON.stringify({ registration_email_from: email || null }) }); setSetting(value); setEmail(value.registration_email_from || ''); setMessage('注册发件地址已保存。') } catch (reason) { setMessage(reason instanceof Error ? reason.message : '设置保存失败。') } finally { setBusy(false) } }
  async function rotateKey() { if (!access.data?.permissions.includes('rotate_keys') || !window.confirm('确认轮换签名密钥吗？')) return; setMessage(''); setBusy(true); try { setKeyResult(await apiFetch<KeyRotationResponse>('/api/v1/admin/keys/rotate', { method: 'POST' })) } catch (reason) { setMessage(reason instanceof Error ? reason.message : '签名密钥轮换失败。') } finally { setBusy(false) } }
  return <>{message && <div className="auth-feedback"><Notice tone={message.includes('已保存') ? 'success' : 'warning'}>{message}</Notice></div>}<div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>注册邮件</h2><p>当前 API 暴露的可配置系统设置。</p></div><Database size={18} color="var(--chenxing-cyan)" /></div>{setting ? <form className="auth-form" onSubmit={save}><Field label="注册邮件发件地址" type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="support@example.com" hint="更新接口要求提供有效邮箱；清空配置需由后端提供专用操作。" /><Button type="submit" icon="save" disabled={busy || !email.trim()}>保存配置</Button></form> : <Notice>正在加载设置。</Notice>}</HudPanel><HudPanel><div className="panel-heading"><div><h2>签名密钥</h2><p>响应只返回 kid 和已发布公钥数量，不包含私钥材料。</p></div><KeyRound size={18} color="var(--chenxing-cyan)" /></div>{keyResult && <div className="list-stack"><div className="list-row"><strong>当前响应 key_id</strong><span className="code-text">{keyResult.key_id}</span></div><div className="list-row"><strong>已发布公钥数量</strong><span>{keyResult.published_key_count}</span></div></div>}<Button variant="danger" icon="refresh-cw" disabled={!access.data?.permissions.includes('rotate_keys') || busy} onClick={() => void rotateKey()}>{access.data?.permissions.includes('rotate_keys') ? '轮换签名密钥' : '缺少 rotate_keys 权限'}</Button></HudPanel></div></>
}
