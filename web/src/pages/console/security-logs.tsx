import { useEffect, useState } from 'react'
import { useLocation, useNavigate } from '../../router'
import { apiFetch, type Paged, type SecurityEvent } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Notice, PageIntro } from '@chenxing/ui'
import { DataTable, DataTableRow, TablePagination, TablePanel } from '@chenxing/ui'
import { formatDate } from '../../data'
import { ActionBadge, PAGE_SIZE } from './security-logs-shared'
import { SecurityLogDetailDrawer } from './security-log-detail'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; data: Paged<SecurityEvent> }
  | { kind: 'error'; message: string }

/**
 * 列表与详情共用一条路由：`/console/logs?id=<事件id>` 在列表之上打开详情抽屉。
 * 保留 ?id= 深链（旧链接、刷新、分享仍然可用），但详情不再是整页替换列表——
 * 表格行详情统一走 Drawer，关闭抽屉回到原来的页码。
 */
export function SecurityLogsPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const rawDetailId = new URLSearchParams(location.search).get('id') ?? ''
  const detailId = /^\d+$/.test(rawDetailId) ? Number(rawDetailId) : NaN
  const hasDetail = Number.isSafeInteger(detailId) && detailId > 0
  return (
    <ConsoleLayout>
      <SecurityLogList />
      {hasDetail ? <SecurityLogDetailDrawer id={detailId} onClose={() => navigate('/console/logs')} /> : null}
    </ConsoleLayout>
  )
}

function SecurityLogList() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(PAGE_SIZE)
  const [state, setState] = useState<LoadState>({ kind: 'loading' })

  useEffect(() => {
    let active = true
    setState({ kind: 'loading' })
    /* 若管理员删除日志导致当前页越界，先收敛回最后一页重新请求，
       避免卡在越界页码的空列表（#372）。
       收敛后 page 严格变小且不低于 1，配合 active 标志不会自循环。 */
    const apply = (data: Paged<SecurityEvent>) => {
      if (!active) return
      const totalPages = Math.max(1, Math.ceil(data.total / data.page_size))
      if (page > totalPages) { setPage(totalPages); return }
      setState({ kind: 'ready', data })
    }
    void apiFetch<Paged<SecurityEvent>>(`/api/v1/auth/security-events?page=${page}&page_size=${pageSize}`)
      .then(apply)
      .catch((reason: unknown) => {
        if (!active) return
        setState({ kind: 'error', message: reason instanceof Error ? reason.message : '安全日志加载失败。' })
      })
    return () => { active = false }
  }, [page, pageSize])

  const result = state.kind === 'ready' ? state.data : null
  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1
  const detailPath = (event: SecurityEvent) => `/console/logs?id=${event.id}`

  return (
    <>
      <PageIntro
        eyebrow="// Security · Logs"
        title="安全日志"
        description="你的登录、会话变更与应用授权活动记录，只展示非敏感字段。"
      />
      <TablePanel
        icon="activity"
        title="活动记录"
        description={result ? `共 ${result.total} 条` : '按时间倒序展示。'}
        notice={
          state.kind === 'error' ? (
            <Notice tone="warning">{state.message}</Notice>
          ) : null
        }
      >
        <DataTable
          minWidth={620}
          columns={['时间', '事件', '应用', '资源']}
          empty={result?.items.length
            ? null
            : state.kind === 'loading'
              ? '正在加载活动记录。'
              : state.kind === 'error'
                ? '无法加载活动记录。'
                : '暂无活动记录。'}
        >
          {result?.items.map((event) => (
            <DataTableRow key={event.id} label={`查看日志 #${event.id} 详情`} onOpen={() => navigate(detailPath(event))}>
              <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
              <td><ActionBadge action={event.action} /></td>
              <td className="chenxing-body text-sm">{event.client_name || (event.client_id ? <span className="chenxing-mono text-xs">{event.client_id}</span> : '—')}</td>
              <td><span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{event.resource_type || '—'}</span></td>
            </DataTableRow>
          ))}
        </DataTable>
        {result && result.total > 0 ? (
          <TablePagination
          page={page}
          totalPages={totalPages}
          total={result.total}
          pageSize={pageSize}
          onPageChange={setPage}
          onPageSizeChange={(size) => { setPageSize(size); setPage(1) }}
        />
        ) : null}
      </TablePanel>
    </>
  )
}
