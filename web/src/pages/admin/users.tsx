import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from '../../router'
import {
  apiFetch, type Paged, type PublicUser,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, EmptyState, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { Select, type SelectOption } from '../../components/select'
import { formatDate, initialOf } from '../../data'
import { AdminGate, useAdminAccess, type AdminAccess } from './shared'
import { AssignPlanDrawer } from './plan-assign'
import { UserCreateDrawer } from './user-create-drawer'

const ROLE_OPTIONS: SelectOption[] = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
  { value: 'owner', label: 'Owner' },
]

const ROLE_LABEL: Record<string, string> = {
  user: '普通用户',
  admin: '管理员',
  owner: 'Owner',
}

/** 角色变更的确认文案：点明变更方向，并在涉及 Owner 时说明其全部管理权限的后果。 */
function roleChangeConfirmText(user: PublicUser, nextRole: string): string {
  const name = user.display_name || user.username
  const current = ROLE_LABEL[user.role] ?? user.role
  const next = ROLE_LABEL[nextRole] ?? nextRole

  let consequence: string
  if (nextRole === 'owner') {
    consequence = '提升为 Owner 后将拥有全部管理权限（用户、套餐、密钥轮换、审计与 OAuth 客户端），并可管理其他管理员与 Owner。'
  } else if (nextRole === 'admin' && user.role === 'user') {
    consequence = '提升为管理员后将获得用户、套餐与审计等后台管理权限。'
  } else if (nextRole === 'admin') {
    consequence = '降级为管理员后将移除 Owner 独有的权限（管理其他管理员与 Owner），保留用户、套餐与审计等后台管理权限。'
  } else if (user.role === 'owner') {
    consequence = '降级为普通用户将立即移除 Owner 的全部管理权限（用户、套餐、密钥轮换、审计与 OAuth 客户端），仅保留普通用户权限。'
  } else {
    consequence = '降级为普通用户将移除其全部后台管理权限。'
  }
  return `确认将 ${name} 的角色从「${current}」改为「${next}」？\n${consequence}`
}

const STATUS_FILTER_OPTIONS: SelectOption[] = [
  { value: '', label: '全部状态' },
  { value: 'active', label: '已启用' },
  { value: 'disabled', label: '已禁用' },
]

export function AdminUsers() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Admin · Users" title="用户管理" description="搜索与管理辰星通行证账号：编辑资料、启用 / 禁用、调整角色。" />
      <AdminGate access={access} permission="manage_users"><UsersTable access={access} /></AdminGate>
    </ConsoleLayout>
  )
}

export function UsersTable({ access }: { access: AdminAccess }) {
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
  const [assignTarget, setAssignTarget] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [created, setCreated] = useState<PublicUser | null>(null)
  const pageSize = 20

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setSearch(current.get('search') || '')
    setStatus(current.get('status') || '')
    setPage(Number(current.get('page') || 1))
  }, [location.search])

  const updateQuery = (nextPage = page) => {
    // 换页或改查询条件后，建号成功提示指向的行可能已不在当前结果里，先收掉。
    setCreated(null)
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
    const nextStatusLabel = nextStatus === 'disabled' ? '已禁用' : '已启用'
    const consequence = nextStatus === 'disabled'
      ? '禁用后将撤销该用户的全部会话，并阻止其登录。'
      : '启用后该用户可以重新登录。'
    if (!window.confirm(`确认将 ${user.display_name || user.username} 的状态改为「${nextStatusLabel}」吗？\n${consequence}`)) return
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
    // 与后端 self_role_change_forbidden 对齐：自己的行已禁用下拉，这里兜底拦截绕过。
    if (user.id === access.data?.user_id) return
    // 两步提交：先确认角色变更方向与 Owner 权限后果，确认后才发起请求。
    if (!window.confirm(roleChangeConfirmText(user, role))) return
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
  // 抽屉标题需要用户名；换页后目标行可能已不在当前结果里，取不到就不渲染抽屉。
  const assignUser = assignTarget !== null ? result?.items.find((item) => item.id === assignTarget) : undefined

  return (
    <HudPanel>
      {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
      {created ? (
        <div className="mb-4">
          <Notice tone="success">已创建用户 {created.username}（{created.email}），请把初始密码通过安全渠道转交本人。</Notice>
        </div>
      ) : null}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Button icon="user-plus" onClick={() => { setCreated(null); setCreateOpen(true) }}>添加用户</Button>
        <div className="flex flex-wrap items-center gap-3">
          <div className="chenxing-field-shell w-full sm:w-72">
            <Icon name="search" className="chenxing-field-icon h-4 w-4" size={16} />
            <input value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索用户 ID / 用户名 / 邮箱" />
          </div>
          <div className="chenxing-field-shell w-36">
            <Icon name="activity" className="chenxing-field-icon h-4 w-4" size={16} />
            <Select value={status} onChange={setStatus} options={STATUS_FILTER_OPTIONS} />
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
              <th className="chenxing-label px-4 py-3">套餐</th>
              <th className="chenxing-label px-4 py-3">创建时间</th>
              <th className="chenxing-label px-4 py-3 text-right">操作</th>
            </tr>
          </thead>
          <tbody>
            {result?.items.map((user) => {
              const isSelf = user.id === access.data?.user_id
              return (
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
                    <div className="flex items-center gap-2">
                      <Select
                        className="!text-sm"
                        value={user.role}
                        disabled={!access.data?.permissions.includes('manage_roles') || isSelf || busy === user.id}
                        onChange={(role) => void setRole(user, role)}
                        options={ROLE_OPTIONS}
                        aria-label={isSelf ? '角色（当前登录账号，不能修改自己的角色）' : '用户角色'}
                      />
                      {isSelf ? (
                        <span className="chenxing-caption text-xs text-[var(--chenxing-muted-foreground)]">不能修改自己的角色</span>
                      ) : null}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <button
                      type="button"
                      className="chenxing-link inline-flex items-center gap-1.5"
                      disabled={!access.data?.permissions.includes('manage_users')}
                      title={access.data?.permissions.includes('manage_users') ? undefined : '套餐分配需要 manage_users 权限'}
                      onClick={() => setAssignTarget(user.id)}
                    >
                      <Icon name="crown" size={13} />
                      分配套餐
                    </button>
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
              )
            })}
          </tbody>
        </table>
      </div>
      {!result?.items.length ? <div className="mt-6"><EmptyState icon="users" title={result ? '没有匹配用户' : '正在加载用户'} /></div> : null}
      <div className="mt-5 flex items-center justify-between gap-3">
        <Button variant="ghost" disabled={page <= 1} onClick={() => updateQuery(page - 1)}>上一页</Button>
        <span className="chenxing-caption">第 {page} / {totalPages} 页 · 共 {result?.total ?? '—'} 条</span>
        <Button variant="ghost" disabled={page >= totalPages} onClick={() => updateQuery(page + 1)}>下一页</Button>
      </div>
      {createOpen ? (
        <UserCreateDrawer
          canManageRoles={Boolean(access.data?.permissions.includes('manage_roles'))}
          onClose={() => setCreateOpen(false)}
          onCreated={(user) => {
            setCreated(user)
            setCreateOpen(false)
            setRefreshKey((value) => value + 1)
          }}
        />
      ) : null}
      {assignTarget !== null && assignUser ? (
        <AssignPlanDrawer
          userId={assignTarget}
          userName={assignUser.display_name || assignUser.username}
          onAssigned={() => setRefreshKey((value) => value + 1)}
          onClose={() => setAssignTarget(null)}
        />
      ) : null}
    </HudPanel>
  )
}
