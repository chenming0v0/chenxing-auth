import { useEffect, useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from '../../router'
import {
  apiFetch, type AdminOverview, type AuditEvent, type ClientSummary,
  type KeyRotationResponse, type Paged, type PublicUser, type RegistrationEmailSetting,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, EmptyState, Field, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { DataTable, TablePanel, TablePagination } from '../../components/data-table'
import { formatDate, initialOf } from '../../data'
import { AdminGate, parsePageParam, useAdminAccess, type AdminAccess } from './shared'

export function AdminAudit() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Admin · Audit" title="审计事件" description="按服务端分页查询安全事件，只展示非敏感索引字段。" />
      <AdminGate access={access} permission="read_audit"><AuditTable /></AdminGate>
    </ConsoleLayout>
  )
}

function AuditTable() {
  const location = useLocation()
  const navigate = useNavigate()
  const params = new URLSearchParams(location.search)
  const [action, setAction] = useState(params.get('action') || '')
  const [resourceType, setResourceType] = useState(params.get('resource_type') || '')
  const [page, setPage] = useState(parsePageParam(params.get('page')))
  const [result, setResult] = useState<Paged<AuditEvent> | null>(null)
  const [error, setError] = useState('')
  const pageSize = 20

  const updateQuery = (nextPage = page) => {
    const next = new URLSearchParams()
    if (action) next.set('action', action)
    if (resourceType) next.set('resource_type', resourceType)
    next.set('page', String(nextPage))
    navigate(`/admin/audit?${next.toString()}`)
  }

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    setAction(current.get('action') || '')
    setResourceType(current.get('resource_type') || '')
    setPage(parsePageParam(current.get('page')))
  }, [location.search])

  useEffect(() => {
    const current = new URLSearchParams(location.search)
    const currentPage = parsePageParam(current.get('page'))
    if (currentPage !== page) { setPage(currentPage); return }
    const query = new URLSearchParams({ page: String(page), page_size: String(pageSize) })
    if (current.get('action')) query.set('action', current.get('action') as string)
    if (current.get('resource_type')) query.set('resource_type', current.get('resource_type') as string)
    let active = true
    void apiFetch<Paged<AuditEvent>>(`/api/v1/admin/audit/query?${query}`)
      .then((value) => { if (active) { setResult(value); setError('') } })
      .catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '审计查询失败。') } })
    return () => { active = false }
  }, [location.search, page])

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1

  return (
    <HudPanel>
      {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="chenxing-h2">审计目录</h2>
        <div className="flex flex-wrap items-center gap-3">
          <input aria-label="按动作筛选" className="chenxing-field w-40" value={action} onChange={(event) => setAction(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="action" />
          <input aria-label="按资源类型筛选" className="chenxing-field w-44" value={resourceType} onChange={(event) => setResourceType(event.target.value)} onKeyDown={(event) => { if (event.key === 'Enter') updateQuery(1) }} placeholder="resource_type" />
          <Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button>
        </div>
      </div>
      <DataTable
        minWidth={860}
        columns={['时间', '动作', '资源', '执行者']}
        empty={result?.items.length ? null : result ? '暂无审计事件' : error ? null : '正在加载审计事件'}
      >
        {result?.items.map((event, index) => (
          <tr key={event.id ?? `${event.created_at}-${index}`}>
            <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
            <td className="chenxing-mono text-sm">{event.action || '—'}</td>
            <td>
              <p className="chenxing-body text-sm">{event.resource_type || '—'}</p>
              {event.resource_id ? <p className="chenxing-caption chenxing-mono">{event.resource_id}</p> : null}
            </td>
            <td>
              <p className="chenxing-body text-sm">{event.actor_type || '—'}</p>
              {event.actor_id ? <p className="chenxing-caption chenxing-mono">{event.actor_id}</p> : null}
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
