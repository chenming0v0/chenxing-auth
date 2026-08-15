import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from '../../router'
import { apiFetch, type Paged, type SecurityEvent } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { EmptyState, Icon, Notice, PageIntro } from '../../components/ui'
import { DataTable, TablePagination, TablePanel } from '../../components/data-table'
import { formatDate } from '../../data'
import { ActionBadge, PAGE_SIZE } from './security-logs-shared'
import { SecurityLogDetail } from './security-log-detail'

type LoadState =
  | { kind: 'loading' }
  | { kind: 'ready'; data: Paged<SecurityEvent> }
  | { kind: 'error'; message: string }

/** 列表与详情共用一条路由：`/console/logs?id=<事件id>` 展示详情，无 id 展示列表。 */
export function SecurityLogsPage() {
  const location = useLocation()
  const detailId = Number.parseInt(new URLSearchParams(location.search).get('id') ?? '', 10)
  return (
    <ConsoleLayout>
      {Number.isInteger(detailId) && detailId > 0 ? <SecurityLogDetail id={detailId} /> : <SecurityLogList />}
    </ConsoleLayout>
  )
}

function SecurityLogList() {
  const navigate = useNavigate()
  const [page, setPage] = useState(1)
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
    void apiFetch<Paged<SecurityEvent>>(`/api/v1/auth/security-events?page=${page}&page_size=${PAGE_SIZE}`)
      .then(apply)
      .catch((reason: unknown) => {
        if (!active) return
        setState({ kind: 'error', message: reason instanceof Error ? reason.message : '安全日志加载失败。' })
      })
    return () => { active = false }
  }, [page])

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
        {/* 桌面端：表格，整行可点进详情 */}
        <div className="hidden sm:block">
          <DataTable
            minWidth={680}
            columns={['时间', '事件', '应用', '资源', { label: '', align: 'right', key: 'detail' }]}
            empty={result?.items.length
              ? null
              : state.kind === 'loading'
                ? '正在加载活动记录…'
                : state.kind === 'error'
                  ? '无法加载活动记录。'
                  : '暂无活动记录。'}
          >
            {result?.items.map((event) => (
              <tr key={event.id} className="cursor-pointer" onClick={() => navigate(detailPath(event))}>
                <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
                <td><ActionBadge action={event.action} /></td>
                <td className="chenxing-body text-sm">{event.client_name || (event.client_id ? <span className="chenxing-mono text-xs">{event.client_id}</span> : '—')}</td>
                <td><span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{event.resource_type || '—'}</span></td>
                <td className="text-right">
                  <Link
                    to={detailPath(event)}
                    className="inline-flex items-center gap-1 text-[var(--chenxing-muted-foreground)] transition-colors hover:text-[var(--chenxing-cyan)]"
                    aria-label={`查看日志 #${event.id} 详情`}
                    onClick={(clickEvent) => clickEvent.stopPropagation()}
                  >
                    <Icon name="arrow-right" size={14} />
                  </Link>
                </td>
              </tr>
            ))}
          </DataTable>
        </div>
        {/* 移动端：键值卡片列表（newapi 风格），与桌面表格同一数据源 */}
        <div className="mt-5 space-y-3 sm:hidden">
          {result?.items.map((event) => (
            <Link
              key={event.id}
              to={detailPath(event)}
              className="block rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] p-4 transition-colors active:border-[var(--chenxing-cyan)]"
              aria-label={`查看日志 #${event.id} 详情`}
            >
              <div className="flex items-center justify-between gap-3">
                <ActionBadge action={event.action} />
                <span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</span>
              </div>
              <dl className="mt-3 space-y-2">
                <div className="flex items-center justify-between gap-3">
                  <dt className="chenxing-caption">应用</dt>
                  <dd className="chenxing-body min-w-0 truncate text-right text-sm">{event.client_name || event.client_id || '—'}</dd>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <dt className="chenxing-caption">资源</dt>
                  <dd className="chenxing-mono text-right text-xs text-[var(--chenxing-muted-foreground)]">{event.resource_type || '—'}</dd>
                </div>
              </dl>
              <p className="chenxing-caption mt-3 flex items-center justify-end gap-1 text-[var(--chenxing-cyan)]">
                详情 <Icon name="arrow-right" size={12} />
              </p>
            </Link>
          ))}
          {!result?.items.length ? (
            <EmptyState
              icon="activity"
              title={state.kind === 'loading'
                ? '正在加载活动记录…'
                : state.kind === 'error'
                  ? '无法加载活动记录'
                  : '暂无活动记录'}
            />
          ) : null}
        </div>
        {result && result.total > result.page_size ? (
          <TablePagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
        ) : null}
      </TablePanel>
    </>
  )
}
