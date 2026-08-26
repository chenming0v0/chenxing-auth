import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from '../../router'
import {
  apiFetch, type AdminUserQueryItem, type Paged, type PublicUser,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Avatar, Badge, Button, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { DataTable, TablePagination } from '../../components/data-table'
import { Select } from '../../components/select'
import { formatDate } from '../../data'
import { AdminGate, parsePageParam, useAdminAccess, type AdminAccess } from './shared'
import { AssignPlanDrawer } from './plan-assign'
import { UserCreateDrawer } from './user-create-drawer'
import { UserCreditDrawer } from './user-credit-drawer'
import { ROLE_OPTIONS, STATUS_FILTER_OPTIONS, STATUS_LABEL, roleChangeConfirmText } from './users-shared'

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
  const [page, setPage] = useState(parsePageParam(params.get('page')))
  const [result, setResult] = useState<Paged<AdminUserQueryItem> | null>(null)
  const [error, setError] = useState('')
  // 行级 busy：多行操作可同时在途，先完成的行只清除自己的标记，不会像单值 busy 那样提前解禁其他行
  const [busy, setBusy] = useState<ReadonlySet<number>>(() => new Set())
  const [refreshKey, setRefreshKey] = useState(0)
  const [assignTarget, setAssignTarget] = useState<number | null>(null)
  const [creditTarget, setCreditTarget] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [created, setCreated] = useState<PublicUser | null>(null)
  const pageSize = 20

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setSearch(current.get('search') || '')
    setStatus(current.get('status') || '')
    setPage(parsePageParam(current.get('page')))
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
    const currentPage = parsePageParam(new URLSearchParams(location.search).get('page'))
    if (currentPage !== page) { setPage(currentPage); return }
    let active = true
    const current = new URLSearchParams(location.search)
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (current.get('search')) query.set('search', current.get('search') as string)
    if (current.get('status')) query.set('status', current.get('status') as string)
    void apiFetch<Paged<AdminUserQueryItem>>(`/api/v1/admin/users/query?${query}`)
      .then((value) => {
        if (!active) return
        const totalPages = Math.max(1, Math.ceil(value.total / value.page_size))
        if (page > totalPages) {
          current.set('page', String(totalPages))
          navigate(`/admin/users?${current.toString()}`, { replace: true })
          return
        }
        setResult(value)
        setError('')
      })
      .catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '用户查询失败。') } })
    return () => { active = false }
  }, [location.search, page, refreshKey])

  async function setUserStatus(user: PublicUser) {
    const permissions = access.data?.permissions ?? []
    const isSelf = user.id === access.data?.user_id
    const needsRolePermission = user.role === 'admin' || user.role === 'owner'
    if (!permissions.includes('manage_users') || isSelf || (needsRolePermission && !permissions.includes('manage_roles'))) return
    const nextStatus = user.status === 'disabled' ? 'active' : 'disabled'
    const nextStatusLabel = nextStatus === 'disabled' ? '已禁用' : '已启用'
    const consequence = nextStatus === 'disabled'
      ? '禁用后将撤销该用户的全部会话，并阻止其登录。'
      : '启用后该用户可以重新登录。'
    if (!window.confirm(`确认将 ${user.display_name || user.username} 的状态改为「${nextStatusLabel}」吗？\n${consequence}`)) return
    setBusy((prev) => new Set(prev).add(user.id))
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/users/${user.id}/${nextStatus}`, { method: 'POST' })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '用户状态更新失败。')
    } finally {
      setBusy((prev) => { const next = new Set(prev); next.delete(user.id); return next })
    }
  }

  async function setRole(user: PublicUser, role: string) {
    if (!access.data?.permissions.includes('manage_roles') || role === user.role) return
    // 与后端 self_role_change_forbidden 对齐：自己的行已禁用下拉，这里兜底拦截绕过。
    if (user.id === access.data?.user_id) return
    // 两步提交：先确认角色变更方向与 Owner 权限后果，确认后才发起请求。
    if (!window.confirm(roleChangeConfirmText(user, role))) return
    setBusy((prev) => new Set(prev).add(user.id))
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/users/${user.id}/role`, { method: 'POST', body: JSON.stringify({ role }) })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '用户角色更新失败。')
    } finally {
      setBusy((prev) => { const next = new Set(prev); next.delete(user.id); return next })
    }
  }

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  // 抽屉标题需要用户名；换页后目标行可能已不在当前结果里，取不到就不渲染抽屉。
  const assignUser = assignTarget !== null ? result?.items.find((item) => item.id === assignTarget) : undefined
  const creditUser = creditTarget !== null ? result?.items.find((item) => item.id === creditTarget) : undefined

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
            <input aria-label="搜索用户" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索用户 ID / 用户名 / 邮箱" />
          </div>
          <div className="chenxing-field-shell w-36">
            <Icon name="activity" className="chenxing-field-icon h-4 w-4" size={16} />
            <Select value={status} onChange={setStatus} options={STATUS_FILTER_OPTIONS} aria-label="按用户状态筛选" />
          </div>
          <Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button>
          <Button variant="ghost" icon="rotate-ccw" onClick={() => { setSearch(''); setStatus(''); navigate('/admin/users?page=1') }}>重置</Button>
        </div>
      </div>

      <DataTable
        minWidth={1080}
        columns={['ID', '用户名', '状态', '角色', '套餐', '创建时间', { label: '操作', align: 'right' }]}
        empty={result?.items.length ? null : result ? '没有匹配用户' : error ? null : '正在加载用户'}
      >
        {result?.items.map((user) => {
          const isSelf = user.id === access.data?.user_id
          const canManageRoles = Boolean(access.data?.permissions.includes('manage_roles'))
          const canManagePrivilegedTarget = canManageRoles || (user.role !== 'admin' && user.role !== 'owner')
          const canManageUsers = Boolean(access.data?.permissions.includes('manage_users'))
          const canAssignPlan = canManageUsers && canManagePrivilegedTarget
          const canCredit = canManageUsers
          const canChangeStatus = canManageUsers && canManagePrivilegedTarget && !isSelf
          return (
            <tr key={user.id}>
                  <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{user.id}</td>
                  <td>
                    <div className="flex items-center gap-3">
                      <Avatar className="h-9 w-9 text-sm" name={user.display_name || user.username} />
                      <div>
                        <p className="chenxing-body text-sm font-semibold">{user.display_name || user.username}</p>
                        <p className="chenxing-caption text-xs">{user.email}</p>
                      </div>
                    </div>
                  </td>
                  <td>
                    <Badge tone={user.status === 'active' ? 'success' : 'warning'}>
                      <Icon name={user.status === 'active' ? 'check' : 'circle-alert'} size={12} />
                      {STATUS_LABEL[user.status] ?? user.status}
                    </Badge>
                  </td>
                  <td>
                    <div className="flex items-center gap-2">
                      <Select
                        className="!text-sm"
                        value={user.role}
                        disabled={!access.data?.permissions.includes('manage_roles') || isSelf || busy.has(user.id)}
                        onChange={(role) => void setRole(user, role)}
                        options={ROLE_OPTIONS}
                        aria-label={isSelf ? '角色（当前登录账号，不能修改自己的角色）' : '用户角色'}
                      />
                      {isSelf ? (
                        <span className="chenxing-caption text-xs text-[var(--chenxing-muted-foreground)]">不能修改自己的角色</span>
                      ) : null}
                    </div>
                  </td>
                  <td>
                    {user.plan ? (
                      <div>
                        <p className="chenxing-body text-sm">{user.plan.name}</p>
                        <p className="chenxing-mono text-xs text-[var(--chenxing-cyan)]">{user.plan.code}</p>
                        {user.plan.expires_at ? <p className="chenxing-caption text-xs">到期 {formatDate(user.plan.expires_at)}</p> : null}
                      </div>
                    ) : <span className="chenxing-caption">未挂载</span>}
                    <button
                      type="button"
                      className="chenxing-link chenxing-row-action"
                      disabled={!canAssignPlan}
                      title={canAssignPlan ? undefined : isSelf ? '不能为自己分配套餐' : '为管理员或 Owner 分配套餐需要 manage_roles 权限'}
                      onClick={() => setAssignTarget(user.id)}
                    >
                      <Icon name="crown" size={13} />
                      分配套餐
                    </button>
                  </td>
                  <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(user.created_at)}</td>
                  <td className="text-right">
                    <div className="inline-flex items-center gap-3">
                      <button
                        type="button"
                        className="chenxing-link chenxing-row-action"
                        disabled={!canCredit}
                        onClick={() => setCreditTarget(user.id)}
                      >
                        <Icon name="wallet" size={13} />
                        充值
                      </button>
                      <button
                        type="button"
                        className={`chenxing-link chenxing-row-action${user.status === 'active' ? ' text-[var(--chenxing-error)]' : ''}`}
                        disabled={!canChangeStatus || busy.has(user.id)}
                        title={canChangeStatus ? undefined : isSelf ? '不能修改自己的状态' : '修改管理员或 Owner 状态需要 manage_roles 权限'}
                        onClick={() => void setUserStatus(user)}
                      >
                        {user.status === 'active' ? '禁用' : '启用'}
                      </button>
                    </div>
                  </td>
              </tr>
            )
          })}
        </DataTable>
        {result && result.total > 0 ? (
          <TablePagination page={page} totalPages={totalPages} total={result.total} onPageChange={updateQuery} />
        ) : null}
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
      {creditTarget !== null && creditUser ? (
        <UserCreditDrawer
          userId={creditTarget}
          userName={creditUser.display_name || creditUser.username}
          onCredited={() => setRefreshKey((value) => value + 1)}
          onClose={() => setCreditTarget(null)}
        />
      ) : null}
    </HudPanel>
  )
}
