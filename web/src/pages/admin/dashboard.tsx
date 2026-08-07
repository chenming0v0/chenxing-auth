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

export function AdminDashboard() {
  const access = useAdminAccess()
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
        {overview ? (
          <div className="flex flex-col gap-6">
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
              <HudPanel className="!p-5">
                <p className="chenxing-label flex items-center gap-2"><Icon name="activity" className="text-[var(--chenxing-warning)]" size={16} />审计事件</p>
                <p className="chenxing-display mt-3 text-3xl font-bold">{overview.audit_events}</p>
                <p className="chenxing-caption mt-1.5 text-[var(--chenxing-warning)]">安全与管理操作索引</p>
              </HudPanel>
            </div>
            <div className="grid gap-6 xl:grid-cols-3">
              <HudPanel className="xl:col-span-1">
                <div className="mb-4">
                  <h2 className="chenxing-h2">管理权限</h2>
                  <p className="chenxing-caption mt-1">每项操作仍由服务端再次校验。</p>
                </div>
                <div className="space-y-2">
                  {access.data?.permissions.map((permission) => (
                    <div key={permission} className="flex items-center justify-between rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] px-4 py-3">
                      <span className="chenxing-mono text-sm">{permission}</span>
                      <Badge tone="success">允许</Badge>
                    </div>
                  ))}
                </div>
              </HudPanel>
              <HudPanel className="xl:col-span-2 !p-0 overflow-hidden">
                <div className="px-6 py-5">
                  <h2 className="chenxing-h2">最近审计</h2>
                  <p className="chenxing-caption mt-1">只展示非敏感索引字段。</p>
                </div>
                {auditError ? <div className="px-6 pb-4"><Notice tone="warning">{auditError}</Notice></div> : null}
                <div className="cx-table-wrap border-0 rounded-none">
                  <table className="cx-table min-w-[720px]">
                    <thead>
                      <tr className="bg-[rgba(4,8,16,0.5)]">
                        <th scope="col" className="chenxing-label px-4 py-3">时间</th>
                        <th scope="col" className="chenxing-label px-4 py-3">事件</th>
                        <th scope="col" className="chenxing-label px-4 py-3">主体</th>
                        <th scope="col" className="chenxing-label px-4 py-3 text-right">资源</th>
                      </tr>
                    </thead>
                    <tbody>
                      {audits.map((event, index) => (
                        <tr key={event.id ?? `${event.created_at}-${index}`}>
                          <td className="chenxing-mono px-4 py-3 text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(event.created_at)}</td>
                          <td className="chenxing-body px-4 py-3 text-sm">{event.action || '—'}</td>
                          <td className="chenxing-body px-4 py-3 text-sm">{event.actor_type || '—'}{event.actor_id ? ` · ${event.actor_id}` : ''}</td>
                          <td className="px-4 py-3 text-right"><span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{event.resource_type || '—'}</span></td>
                        </tr>
                      ))}
                      {!audits.length ? (
                        <tr><td colSpan={4} className="px-4 py-10 text-center"><span className="chenxing-caption">{auditError ? '最近审计暂时不可用。' : access.data?.permissions.includes('read_audit') ? '暂无审计事件。' : '暂无审计事件或缺少 read_audit 权限'}</span></td></tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </HudPanel>
            </div>
          </div>
        ) : null}
      </AdminGate>
    </ConsoleLayout>
  )
}
