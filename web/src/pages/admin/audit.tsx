import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from '../../router'
import { apiFetch, type AuditEvent, type Paged } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Button, Icon, Notice, PageIntro } from '../../components/ui'
import { DataTable, TablePanel, TablePagination } from '../../components/data-table'
import { Select } from '../../components/select'
import { formatDate } from '../../data'
import { AdminGate, parsePageParam, useAdminAccess } from './shared'
import { AuditDetailDrawer } from './audit-detail-drawer'
import {
  ACTION_FILTER_OPTIONS, ActionBadge, RESOURCE_FILTER_OPTIONS, SeverityBadge,
  formatActor, resourceLabel, withCurrentOption,
} from './audit-labels'

export function AdminAudit() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Admin · Audit"
        title="审计日志"
        description="按时间倒序查看安全与管理操作，只展示脱敏后的索引字段。"
      />
      <AdminGate access={access} permission="read_audit"><AuditTable /></AdminGate>
    </ConsoleLayout>
  )
}

export function AuditTable() {
  const location = useLocation()
  const navigate = useNavigate()
  const params = new URLSearchParams(location.search)
  const [action, setAction] = useState(params.get('action') || '')
  const [resourceType, setResourceType] = useState(params.get('resource_type') || '')
  const [page, setPage] = useState(parsePageParam(params.get('page')))
  const [result, setResult] = useState<Paged<AuditEvent> | null>(null)
  const [error, setError] = useState('')
  const [detail, setDetail] = useState<AuditEvent | null>(null)
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
      .then((value) => {
        if (!active) return
        const totalPages = Math.max(1, Math.ceil(value.total / value.page_size))
        if (page > totalPages) {
          current.set('page', String(totalPages))
          navigate(`/admin/audit?${current.toString()}`, { replace: true })
          return
        }
        setResult(value)
        setError('')
      })
      .catch((reason: unknown) => { if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '审计查询失败。') } })
    return () => { active = false }
  }, [location.search, page])

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  const actionOptions = withCurrentOption(ACTION_FILTER_OPTIONS, action)
  const resourceOptions = withCurrentOption(RESOURCE_FILTER_OPTIONS, resourceType)

  return (
    <>
      <TablePanel
        icon="activity"
        title="事件列表"
        description="点击一行查看脱敏后的详情。未知历史动作会保留原始代码。"
      >
        {error ? <Notice tone="warning">{error}</Notice> : null}
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <div className="chenxing-field-shell w-56">
            <Select value={action} onChange={setAction} options={actionOptions} aria-label="事件类型" />
          </div>
          <div className="chenxing-field-shell w-52">
            <Select value={resourceType} onChange={setResourceType} options={resourceOptions} aria-label="资源类型" />
          </div>
          <Button variant="ghost" icon="search" onClick={() => updateQuery(1)}>查询</Button>
          <Button variant="ghost" icon="rotate-ccw" onClick={() => navigate('/admin/audit?page=1')}>重置</Button>
        </div>
        <DataTable
          minWidth={920}
          columns={['时间', '事件', '级别', '执行者', '资源', { label: '操作', align: 'right' }]}
          empty={result?.items.length ? null : result ? '暂无审计事件' : error ? null : '正在加载审计事件'}
        >
          {result?.items.map((event, index) => (
            <tr
              key={event.id ?? `${event.created_at}-${index}`}
              className="cursor-pointer"
              onClick={() => setDetail(event)}
            >
              <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
              <td><ActionBadge action={event.action || ''} /></td>
              <td><SeverityBadge action={event.action || ''} /></td>
              <td className="chenxing-body text-sm">{formatActor(event.actor_type, event.actor_id)}</td>
              <td>
                <p className="chenxing-body text-sm">{resourceLabel(event.resource_type)}</p>
                {event.resource_id ? <p className="chenxing-caption chenxing-mono">{event.resource_id}</p> : null}
              </td>
              <td className="text-right" onClick={(clickEvent) => clickEvent.stopPropagation()}>
                <button type="button" className="chenxing-link chenxing-row-action" onClick={() => setDetail(event)}>
                  <Icon name="arrow-right" size={13} />
                  详情
                </button>
              </td>
            </tr>
          ))}
        </DataTable>
        {result && result.total > 0 ? (
          <TablePagination page={page} totalPages={totalPages} total={result.total} onPageChange={updateQuery} />
        ) : null}
      </TablePanel>
      {detail ? <AuditDetailDrawer event={detail} onClose={() => setDetail(null)} /> : null}
    </>
  )
}
