import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from '../../router'
import {
  apiFetch, type AdminOverview, type AuditEvent, type ClientSummary,
  type KeyRotationResponse, type Paged, type PublicUser, type RegistrationEmailSetting,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, EmptyState, Field, HudPanel, Icon, Notice, PageIntro } from '@chenxing/ui'
import { DataTable, TablePanel, TablePagination } from '@chenxing/ui'
import { formatDate, initialOf } from '../../data'
import { AdminGate, parsePageParam, useAdminAccess, type AdminAccess } from './shared'

export function AdminClients() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Admin · Clients" title="OAuth 客户端" description="服务端分页查询全局 Client，不展示 Secret 或 Secret 哈希。" />
      <AdminGate access={access} permission="manage_clients"><ClientsTable access={access} /></AdminGate>
    </ConsoleLayout>
  )
}

export function ClientsTable({ access }: { access: AdminAccess }) {
  const location = useLocation()
  const navigate = useNavigate()
  const params = new URLSearchParams(location.search)
  const [search, setSearch] = useState(params.get('search') || '')
  const [page, setPage] = useState(parsePageParam(params.get('page')))
  const [result, setResult] = useState<Paged<ClientSummary> | null>(null)
  const [error, setError] = useState('')
  // 行级 busy：多行操作可同时在途，先完成的行只清除自己的标记，不会像单值 busy 那样提前解禁其他行
  const [busy, setBusy] = useState<ReadonlySet<string>>(() => new Set())
  const [refreshKey, setRefreshKey] = useState(0)
  const pageSize = 20

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setSearch(current.get('search') || '')
    setPage(parsePageParam(current.get('page')))
  }, [location.search])

  const updateQuery = (nextPage = page) => {
    const next = new URLSearchParams()
    if (search) next.set('search', search)
    next.set('page', String(nextPage))
    navigate(`/admin/clients?${next.toString()}`)
  }

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    const currentPage = parsePageParam(current.get('page'))
    if (currentPage !== page) { setPage(currentPage); return }
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (current.get('search')) query.set('search', current.get('search') as string)
    let active = true
    void apiFetch<Paged<ClientSummary>>(`/api/v1/admin/clients/query?${query}`)
      .then((value) => {
        if (!active) return
        const totalPages = Math.max(1, Math.ceil(value.total / value.page_size))
        if (page > totalPages) {
          current.set('page', String(totalPages))
          navigate(`/admin/clients?${current.toString()}`, { replace: true })
          return
        }
        setResult(value)
        setError('')
      })
      .catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : 'Client 查询失败。') } })
    return () => { active = false }
  }, [location.search, page, refreshKey])

  async function setClientStatus(client: ClientSummary) {
    if (!access.data?.permissions.includes('manage_clients')) return
    // 请求在途时按钮已 disabled，这里兜底拦截：双击的第二个 click 若在 re-render 前被派发，也不会发出并发请求。
    if (busy.has(client.client_id)) return
    const action = client.status === 'active' ? 'disable' : 'enable'
    const actionLabel = action === 'disable' ? '禁用' : '启用'
    const consequence = action === 'disable'
      ? '禁用后，该 OAuth 应用将无法发起新的授权，也无法获取新的令牌。'
      : '启用后，该 OAuth 应用可以重新发起授权并获取令牌。'
    if (!window.confirm(`确认${actionLabel} ${client.client_name} 吗？\n${consequence}`)) return
    setBusy((prev) => new Set(prev).add(client.client_id))
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/clients/${encodeURIComponent(client.client_id)}/${action}`, { method: 'POST' })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Client 状态更新失败。')
    } finally {
      setBusy((prev) => { const next = new Set(prev); next.delete(client.client_id); return next })
    }
  }

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1

  return (
    <HudPanel>
      {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="chenxing-h2">Client 目录</h2>
        <div className="flex flex-wrap items-center gap-3">
          <div className="chenxing-field-shell w-full sm:w-72">
            <Icon name="search" className="chenxing-field-icon h-4 w-4" size={16} />
            <input aria-label="搜索客户端" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="搜索 Client 或名称" />
          </div>
          <Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button>
        </div>
      </div>
      <DataTable
        minWidth={920}
        columns={['Client', 'Owner', 'Redirect URI', '状态', { label: '操作', align: 'right' }]}
        empty={result?.items.length ? null : result ? '没有匹配 Client' : error ? null : '正在加载 Client'}
      >
        {result?.items.map((client) => (
          <tr key={client.client_id}>
            <td>
              <p className="chenxing-body text-sm font-semibold">{client.client_name}</p>
              <p className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{client.client_id}</p>
            </td>
            <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{client.owner_user_id ?? '—'}</td>
            <td><p className="chenxing-caption max-w-xs truncate">{client.redirect_uris.join(' · ')}</p></td>
            <td><Badge tone={client.status === 'active' ? 'success' : 'warning'}>{client.status}</Badge></td>
            <td className="text-right">
              <Button variant={client.status === 'active' ? 'danger' : 'ghost'} icon={client.status === 'active' ? 'x' : 'check'} onClick={() => void setClientStatus(client)} disabled={busy.has(client.client_id)}>
                {client.status === 'active' ? '禁用' : '启用'}
              </Button>
            </td>
          </tr>
        ))}
      </DataTable>
      {result && result.total > 0 ? (
        <TablePagination page={page} totalPages={totalPages} total={result.total} onPageChange={updateQuery} />
      ) : null}
    </HudPanel>
  )
}
