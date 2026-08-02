import { useEffect, useState, type FormEvent } from 'react'
import { Activity, ArrowUpRight, Check, Cloud, LockKeyhole, ShieldCheck, UserRound } from 'lucide-react'
import { Link, useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, getEntitlements, type EntitlementItem, type EntitlementsResponse, type OwnedOAuthClient, type SessionItem, type UserMe } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, CopyValue, Field, HudPanel, Notice, PageHeader } from '../../components/ui'

function formatDate(value: string): string {
  const date = new Date(value)
  return Number.isNaN(date.valueOf()) ? '时间不可用' : date.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
}

function entitlementView(item: EntitlementItem) {
  const numericLimit = typeof item.limit === 'number' ? item.limit : null
  const hasLimit = numericLimit !== null
  const unlimited = item.limit === null
  const remaining = item.remaining ?? (numericLimit !== null ? Math.max(numericLimit - item.used, 0) : null)
  const progress = numericLimit !== null && numericLimit > 0 ? Math.min(item.used / numericLimit, 1) * 100 : numericLimit !== null ? 100 : 0
  return { hasLimit, unlimited, remaining, progress }
}

function useEntitlements() {
  const [data, setData] = useState<EntitlementsResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const load = (force = false) => {
    setLoading(true)
    setError('')
    void getEntitlements(force).then(setData).catch((reason: unknown) => setError(reason instanceof Error ? reason.message : '权益数据加载失败。')).finally(() => setLoading(false))
  }
  useEffect(() => { load() }, [])
  return { data, error, loading, retry: () => load(true) }
}

function EntitlementRows({ items }: { items: EntitlementItem[] }) {
  return <div className="list-stack">{items.map((item) => {
    const view = entitlementView(item)
    return <div className="metric-line" key={item.key}><header><span>{item.label}</span><strong>{item.used}{view.hasLimit ? ` / ${item.limit}` : view.unlimited ? ' / ∞' : ''}</strong></header>{view.hasLimit && <div className="progress-track"><span style={{ width: `${view.progress}%` }} /></div>}<small className="field-hint">{view.hasLimit ? `剩余 ${view.remaining}` : view.unlimited ? '无限额度' : '仅展示当前数值'}</small></div>
  })}</div>
}

export function ConsoleOverview() {
  const { user } = useAuth()
  const { data: entitlements, error: entitlementError, loading: entitlementLoading, retry } = useEntitlements()
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let active = true
    void Promise.all([
      apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients'),
      apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions'),
    ]).then(([clientResponse, sessionResponse]) => {
      if (!active) return
      setClients(clientResponse.items)
      setSessions(sessionResponse.items)
    }).catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '账户摘要加载失败。') }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])
  return <ConsoleLayout><PageHeader eyebrow="ACCOUNT / OVERVIEW" title={`欢迎回来，${user?.display_name || user?.username || '用户'}`} description="这里显示来自认证服务的账户、会话和权益摘要。" action={<Link className="chenxing-btn-primary" to="/console/integrate">接入应用</Link>} />
    {(error || entitlementError) && <div className="auth-feedback"><Notice tone="warning">{error || entitlementError}<button className="text-link" type="button" onClick={retry}>重试</button></Notice></div>}
    <div className="stat-grid"><HudPanel className="stat-panel"><header><span>活跃会话</span><Activity className="stat-icon" size={19} /></header><h2>{loading ? '—' : sessions.length}</h2><footer><span>服务端当前列表</span><Badge tone="success">LIVE</Badge></footer></HudPanel><HudPanel className="stat-panel"><header><span>OAuth 应用</span><ShieldCheck className="stat-icon" size={19} /></header><h2>{loading ? '—' : clients.length}</h2><footer><span>当前账号拥有</span><Badge tone="success">LIVE</Badge></footer></HudPanel><HudPanel className="stat-panel"><header><span>当前套餐</span><Cloud className="stat-icon" size={19} /></header><h2>{entitlementLoading ? '—' : entitlements?.plan.code || '—'}</h2><footer><span>{entitlements?.plan.name || '等待服务端数据'}</span><Badge tone="success">CURRENT</Badge></footer></HudPanel></div>
    <div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>账户状态</h2><p>公开资料和当前会话有效期</p></div><UserRound size={18} color="var(--chenxing-cyan)" /></div><div className="activity-list"><div className="activity-row"><span><strong>{user?.display_name || user?.username}</strong><small>{user?.email}</small></span><Badge tone="success">{user?.status || 'active'}</Badge></div><div className="activity-row"><span><strong>当前会话</strong><small>到期时间由服务端返回</small></span><small>{user ? formatDate(user.current_session_expires_at) : '—'}</small></div></div></HudPanel><HudPanel><div className="panel-heading"><div><h2>当前权益</h2><p>{entitlements ? `${entitlements.plan.name} · ${entitlements.plan.validity === 'permanent' ? '永久有效' : formatDate(entitlements.plan.validity)}` : '服务端权益数据'}</p></div><Cloud size={18} color="var(--chenxing-cyan)" /></div>{entitlements ? <EntitlementRows items={entitlements.entitlements} /> : <Notice>{entitlementLoading ? '正在加载权益数据。' : '暂无权益数据。'}</Notice>}<Link className="chenxing-link" to="/console/plans">查看套餐权益 <ArrowUpRight size={14} /></Link></HudPanel></div>
  </ConsoleLayout>
}

export function ConsolePlans() {
  const { data, error, loading, retry } = useEntitlements()
  return <ConsoleLayout><PageHeader eyebrow="ACCOUNT / PLANS" title="套餐与权益" description="套餐定义和额度均来自服务端。升级动作需要产品侧提供对应的后端流程。" />{error && <div className="auth-feedback"><Notice tone="warning">{error}<button className="text-link" type="button" onClick={retry}>重试</button></Notice></div>}{loading && <HudPanel><Notice>正在加载服务端权益数据。</Notice></HudPanel>}{data && <><HudPanel className="current-plan"><div className="panel-heading"><div><span className="eyebrow">CURRENT PLAN</span><h2>{data.plan.name} · {data.plan.code}</h2><p>{data.plan.description || '服务端未提供套餐描述。'}</p></div><Badge tone="success"><Check size={13} />当前套餐</Badge></div><div className="plan-summary"><div><strong>{data.plan.validity === 'permanent' ? '永久' : formatDate(data.plan.validity)}</strong><span>有效期</span></div><div><strong>{data.entitlements.length}</strong><span>已配置权益</span></div><div><strong>服务端</strong><span>数据来源</span></div></div></HudPanel><div className="plans-grid">{data.entitlements.map((item) => <HudPanel className="plan-card" key={item.key}><div className="panel-heading"><div><span className="chenxing-chip">{item.key}</span><h2>{item.label}</h2></div><Badge tone="success">实时</Badge></div><EntitlementRows items={[item]} /><div className="plan-description">{typeof item.limit === 'number' ? '达到上限后相关操作会受到服务端限制。' : item.limit === null ? '该权益由服务端标记为无限额度。' : '该权益没有数值上限概念。'}</div><Button variant="ghost" icon="arrow-up-right" disabled title="升级流程尚未提供">联系支持处理升级</Button></HudPanel>)}</div><div className="auth-feedback"><Notice tone="info">当前 API 只提供权益查询，页面不会将选择操作伪装成已扣款或已升级。</Notice></div></>}</ConsoleLayout>
}

export function ConsoleProfile() {
  const { user, clear, refresh } = useAuth()
  const navigate = useNavigate()
  const [displayName, setDisplayName] = useState('')
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [showPassword, setShowPassword] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [message, setMessage] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { setDisplayName(user?.display_name || '') }, [user?.display_name])
  const loadSessions = () => { void apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions').then((response) => setSessions(response.items)).catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '会话列表加载失败。')) }
  useEffect(() => { loadSessions() }, [])

  async function updateProfile(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    setBusy(true)
    try {
      await apiFetch<UserMe>('/api/v1/auth/me', { method: 'PATCH', body: JSON.stringify({ display_name: displayName || null }) })
      await refresh()
      setMessage('资料已保存。')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '资料保存失败。')
    } finally { setBusy(false) }
  }

  async function updatePassword(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    if (newPassword.length < 10) { setMessage('新密码至少需要 10 位字符。'); return }
    setBusy(true)
    try {
      await apiFetch<void>('/api/v1/auth/password', { method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) })
      clear()
      navigate('/login?returnTo=%2Fconsole%2Fprofile')
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '密码修改失败。')
    } finally { setBusy(false) }
  }

  async function revokeSession(session: SessionItem) {
    if (!window.confirm(session.current ? '撤销当前会话后需要重新登录，继续吗？' : '确认撤销这个会话吗？')) return
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/sessions/${session.id}`, { method: 'DELETE' })
      if (session.current) { clear(); navigate('/login?returnTo=%2Fconsole%2Fprofile'); return }
      loadSessions()
    } catch (error) { setMessage(error instanceof Error ? error.message : '会话撤销失败。') }
  }

  return <ConsoleLayout><PageHeader eyebrow="ACCOUNT / PROFILE" title="个人信息" description="管理服务端资料、登录凭据和活跃会话。" action={<Badge tone="success"><ShieldCheck size={13} />身份已验证</Badge>} />{message && <div className="auth-feedback"><Notice tone={message.includes('已保存') ? 'success' : 'warning'}>{message}</Notice></div>}<div className="content-grid grid-2"><HudPanel><div className="panel-heading"><div><h2>基本资料</h2><p>页面只展示公开用户资料。</p></div><UserRound size={18} color="var(--chenxing-cyan)" /></div><form className="auth-form" onSubmit={updateProfile}><Field label="显示名称" value={displayName} onChange={(event) => setDisplayName(event.target.value)} /><Field label="用户名" value={user?.username || ''} readOnly /><Field label="邮箱地址" type="email" value={user?.email || ''} readOnly hint="邮箱修改需要单独的验证流程。" /><Button type="submit" icon="check" disabled={busy}>保存资料</Button></form></HudPanel><HudPanel><div className="panel-heading"><div><h2>安全设置</h2><p>密码成功修改后所有会话都会被撤销。</p></div><LockKeyhole size={18} color="var(--chenxing-cyan)" /></div>{showPassword ? <form className="auth-form" onSubmit={updatePassword}><Field label="当前密码" type="password" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required /><Field label="新密码" type="password" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} required hint="至少 10 位字符。" /><div className="panel-actions"><Button type="submit" icon="key-round" disabled={busy}>确认修改</Button><Button type="button" variant="ghost" onClick={() => setShowPassword(false)}>取消</Button></div></form> : <Button variant="ghost" icon="key-round" onClick={() => setShowPassword(true)}>修改密码</Button>}</HudPanel></div><HudPanel><div className="panel-heading"><div><h2>活跃会话</h2><p>只显示会话时间和当前标记，不展示 IP、User-Agent 或 payload。</p></div><LockKeyhole size={18} color="var(--chenxing-cyan)" /></div>{sessions.length ? <div className="list-stack">{sessions.map((session) => <div className="list-row" key={session.id}><div><strong>{session.current ? '当前会话' : '其他会话'}</strong><small>创建于 {formatDate(session.created_at)} · 到期 {formatDate(session.expires_at)}</small></div><div className="panel-actions">{session.current && <Badge tone="success">当前</Badge>}<Button variant="danger" icon="x" onClick={() => void revokeSession(session)}>撤销</Button></div></div>)}</div> : <div className="empty-state"><LockKeyhole size={24} /><strong>暂无活跃会话</strong></div>}</HudPanel></ConsoleLayout>
}

export function AuthorizedApps() {
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [message, setMessage] = useState('')
  useEffect(() => { void apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients').then((response) => setClients(response.items)).catch((reason: unknown) => setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。')) }, [])
  return <ConsoleLayout><PageHeader eyebrow="ACCOUNT / AUTHORIZED APPS" title="已授权应用" description="当前 API 提供的是账号拥有的 OAuth 项目列表；授权撤销需要后端提供对应的用户授权撤销路由。" action={<Link className="chenxing-btn-ghost" to="/console/integrate">接入应用</Link>} />{message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}<HudPanel><div className="panel-heading"><div><h2>OAuth 项目</h2><p>{clients.length} 个服务端项目</p></div><ShieldCheck size={18} color="var(--chenxing-cyan)" /></div>{clients.length ? <div className="list-stack">{clients.map((client) => <div className="list-row app-list-row" key={client.client_id}><div className="app-list-main"><span className="app-mark"><ShieldCheck size={19} /></span><span><strong>{client.client_name}</strong><small>{client.redirect_uris.join(' · ')}</small><small className="code-text">{client.scopes.join(' · ')}</small></span></div><Badge tone={client.status === 'active' ? 'success' : 'warning'}>{client.status}</Badge></div>)}</div> : <div className="empty-state"><ShieldCheck size={24} /><strong>暂无 OAuth 项目</strong><span>从接入应用开始创建你的第一个项目。</span></div>}<div className="auth-feedback"><Notice tone="info">当前 OpenAPI 没有用户授权撤销端点，因此不会把“禁用项目”误当成“撤销授权”。</Notice></div></HudPanel></ConsoleLayout>
}
