import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from '../../router'
import {
  apiFetch, type AdminOverview, type AuditEvent, type ClientSummary,
  type KeyRotationResponse, type Paged, type PublicUser, type RegistrationEmailSetting,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, EmptyState, Field, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { formatDate, initialOf } from '../../data'
import { AdminGate, useAdminAccess, type AdminAccess } from './shared'

export function AdminUsers() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Admin · Users" title="用户管理" description="搜索与管理辰星通行证账号：编辑资料、启用 / 禁用、调整角色。" />
      <AdminGate access={access} permission="manage_users"><UsersTable access={access} /></AdminGate>
    </ConsoleLayout>
  )
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

  const updateQuery = (nextPage = page) => {
    const next = new URLSearchParams()
    if (search) next.set('search', search)
    if (status) next.set('status', status)
    next.set('page', String(nextPage))
    navigate(`/admin/users?${next.toString()}`)
  }

  useEffect(() => {
    const currentPage = Number(new URLSearchParams(location.search).get('page') || 1)
    if (currentPage !== page) { setPage(currentPage); return }
    let active = true
    const current = new URLSearchParams(location.search)
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (current.get('search')) query.set('search', current.get('search') as string)
    if (current.get('status')) query.set('status', current.get('status') as string)
    void apiFetch<Paged<PublicUser>>(`/api/v1/admin/users/query?${query}`)
      .then((value) => { if (active) setResult(value) })
      .catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '用户查询失败。') } })
    return () => { active = false }
  }, [location.search, page, refreshKey])

  async function setUserStatus(user: PublicUser) {
    if (!access.data?.permissions.includes('manage_users')) return
    const nextStatus = user.status === 'disabled' ? 'active' : 'disabled'
    if (!window.confirm(`确认将 ${user.display_name || user.username} 设为 ${nextStatus} 吗？`)) return
    setBusy(user.id)
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/users/${user.id}/${nextStatus}`, { method: 'POST' })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '用户状态更新失败。')
    } finally {
      setBusy(null)
    }
  }

  async function setRole(user: PublicUser, role: string) {
    if (!access.data?.permissions.includes('manage_roles') || role === user.role) return
    setBusy(user.id)
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/users/${user.id}/role`, { method: 'POST', body: JSON.stringify({ role }) })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '用户角色更新失败。')
    } finally {
      setBusy(null)
    }
  }

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1

  return (
    <HudPanel>
      {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button icon="user-plus" disabled title="创建用户接口尚未接入前端">添加用户</Button>
        <div className="flex flex-wrap items-center gap-3">
          <div className="chenxing-field-shell w-full sm:w-72">
            <Icon name="search" className="chenxing-field-icon h-4 w-4" size={16} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索用户 ID / 用户名 / 邮箱" />
          </div>
          <div className="chenxing-field-shell w-36">
            <Icon name="activity" className="chenxing-field-icon h-4 w-4" size={16} />
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">全部状态</option>
              <option value="active">已启用</option>
              <option value="disabled">已禁用</option>
            </select>
          </div>
          <Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button>
          <Button variant="ghost" icon="rotate-ccw" onClick={() => { setSearch(''); setStatus(''); navigate('/admin/users?page=1') }}>重置</Button>
        </div>
      </div>

      <div className="mt-5 overflow-x-auto rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)]">
        <table className="w-full min-w-[1080px] text-left">
          <thead>
            <tr className="border-b border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.5)]">
              <th className="chenxing-label px-4 py-3">ID</th>
              <th className="chenxing-label px-4 py-3">用户名</th>
              <th className="chenxing-label px-4 py-3">状态</th>
              <th className="chenxing-label px-4 py-3">角色</th>
              <th className="chenxing-label px-4 py-3">创建时间</th>
              <th className="chenxing-label px-4 py-3 text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {result?.items.map((user) => (
              <tr key={user.id} className="border-t border-[var(--chenxing-border)]">
                <td className="chenxing-mono px-4 py-3 text-xs text-[var(--chenxing-muted-foreground)]">{user.id}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-3">
                    <span className="chenxing-avatar h-9 w-9 text-sm">{initialOf(user.display_name || user.username)}</span>
                    <div>
                      <p className="chenxing-body text-sm font-semibold">{user.display_name || user.username}</p>
                      <p className="chenxing-caption text-xs">{user.email}</p>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <Badge tone={user.status === 'active' ? 'success' : 'warning'}>
                    <Icon name={user.status === 'active' ? 'check' : 'circle-alert'} size={12} />
                    {user.status === 'active' ? '已启用' : user.status}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  <select
                    className="chenxing-field !py-2 !text-sm"
                    value={user.role}
                    disabled={!access.data?.permissions.includes('manage_roles') || busy === user.id}
                    onChange={(event) => void setRole(user, event.target.value)}
                  >
                    <option value="user">普通用户</option>
                    <option value="admin">管理员</option>
                    <option value="owner">Owner</option>
                  </select>
                </td>
                <td className="chenxing-mono px-4 py-3 text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(user.created_at)}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    type="button"
                    className={`chenxing-link${user.status === 'active' ? ' text-[var(--chenxing-error)]' : ''}`}
                    disabled={!access.data?.permissions.includes('manage_users') || busy === user.id}
                    onClick={() => void setUserStatus(user)}
                  >
                    {user.status === 'active' ? '禁用' : '启用'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!result?.items.length ? <div className="mt-6"><EmptyState icon="users" title={result ? '没有匹配用户' : '正在加载用户'} /></div> : null}
      <div className="mt-5 flex items-center justify-between gap-3">
        <Button variant="ghost" disabled={page <= 1} onClick={() => updateQuery(page - 1)}>上一页</Button>
        <span className="chenxing-caption">第 {page} / {totalPages} 页 · 共 {result?.total ?? '—'} 条</span>
        <Button variant="ghost" disabled={page >= totalPages} onClick={() => updateQuery(page + 1)}>下一页</Button>
      </div>
    </HudPanel>
  )
}

