import { useEffect, useState } from 'react'
import { Link, useNavigate } from '../../router'
import { apiFetch, type AdminOverview, type AuditEvent, type Paged } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { HudPanel, Icon, Notice, PageIntro } from '@chenxing/ui'
import { DataTable, TablePanel } from '@chenxing/ui'
import { formatDate } from '../../data'
import { AdminGate, useAdminAccess } from './shared'
import { ActionBadge, formatActor, resourceLabel } from './audit-labels'

export function AdminDashboard() {
  const access = useAdminAccess()
  const navigate = useNavigate()
  const [overview, setOverview] = useState<AdminOverview | null>(null)
  const [audits, setAudits] = useState<AuditEvent[]>([])
  const [error, setError] = useState('')
  const [auditError, setAuditError] = useState('')

  useEffect(() => {
    const permissions = access.data?.permissions
    if (!permissions?.includes('manage_clients')) return
    let active = true
    setError('')
    setAuditError('')

    void apiFetch<AdminOverview>('/api/v1/admin/overview')
      .then((value) => { if (active) setOverview(value) })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : '概览数据加载失败。')
      })

    if (!permissions.includes('read_audit')) {
      setAudits([])
    } else {
      void apiFetch<Paged<AuditEvent>>('/api/v1/admin/audit/query?page=1&page_size=5')
        .then((value) => { if (active) setAudits(value.items) })
        .catch((reason: unknown) => {
          if (!active) return
          setAudits([])
          setAuditError(reason instanceof Error ? reason.message : '最近审计加载失败。')
        })
    }

    return () => { active = false }
  }, [access.data])

  return (
    <ConsoleLayout>
      <PageIntro eyebrow="// Admin · Dashboard" title="仪表盘" description="辰星认证中枢的运行状态、认证流量与安全事件总览。" />
      <AdminGate access={access} permission="manage_clients">
        {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
        <div className="flex flex-col gap-6">
          {overview ? (
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <HudPanel className="!p-5">
                <p className="chenxing-label flex items-center gap-2"><Icon name="users" className="text-[var(--chenxing-cyan)]" size={16} />注册用户</p>
                <p className="chenxing-display mt-3 text-3xl font-bold">{overview.users}</p>
                <p className="chenxing-caption mt-1.5">服务端总数</p>
              </HudPanel>
              <HudPanel className="!p-5">
                <p className="chenxing-label flex items-center gap-2"><Icon name="layers" className="text-[var(--chenxing-cyan)]" size={16} />接入客户端</p>
                <p className="chenxing-display mt-3 text-3xl font-bold">{overview.oauth_clients}</p>
                <p className="chenxing-caption mt-1.5">OAuth / OIDC 项目</p>
              </HudPanel>
              <HudPanel className="!p-5">
                <p className="chenxing-label flex items-center gap-2"><Icon name="shield-check" className="text-[var(--chenxing-cyan)]" size={16} />管理员</p>
                <p className="chenxing-display mt-3 text-3xl font-bold">{overview.administrators}</p>
                <p className="chenxing-caption mt-1.5">具备管理会话的账户</p>
              </HudPanel>
              <Link to="/admin/audit" className="block">
                <HudPanel className="!p-5">
                  <p className="chenxing-label flex items-center gap-2"><Icon name="activity" className="text-[var(--chenxing-warning)]" size={16} />审计事件</p>
                  <p className="chenxing-display mt-3 text-3xl font-bold">{overview.audit_events}</p>
                  <p className="chenxing-caption mt-1.5">查看审计日志</p>
                </HudPanel>
              </Link>
            </div>
          ) : null}
          <TablePanel
            icon="activity"
            title="最近审计"
            description="只展示脱敏后的索引字段。"
            action={<Link to="/admin/audit" className="chenxing-link">查看全部</Link>}
            notice={auditError ? <Notice tone="warning">{auditError}</Notice> : null}
          >
            <DataTable
              minWidth={720}
              columns={['时间', '事件', '执行者', { label: '资源', align: 'right' }]}
              empty={audits.length ? null : auditError ? '最近审计暂时不可用。' : access.data?.permissions.includes('read_audit') ? '暂无审计事件。' : '暂无审计事件或缺少 read_audit 权限'}
            >
              {audits.map((event, index) => (
                <tr
                  key={event.id ?? `${event.created_at}-${index}`}
                  className="cursor-pointer"
                  onClick={() => navigate(event.action ? `/admin/audit?action=${encodeURIComponent(event.action)}` : '/admin/audit')}
                >
                  <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
                  <td><ActionBadge action={event.action || ''} /></td>
                  <td className="chenxing-body text-sm">{formatActor(event.actor_type, event.actor_id)}</td>
                  <td className="text-right"><span className="chenxing-body text-sm">{resourceLabel(event.resource_type)}</span></td>
                </tr>
              ))}
            </DataTable>
          </TablePanel>
        </div>
      </AdminGate>
    </ConsoleLayout>
  )
}
