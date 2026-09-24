import { useEffect, useState } from 'react'
import { ApiError, apiFetch, type SecurityEventDetail } from '../../api'
import { Badge, Button, Drawer, Icon, Notice } from '@chenxing/ui'
import { formatDate } from '../../data'
import { ActionBadge } from './security-logs-shared'

/** 敏感值默认打码，点眼睛切换明文；值缺失（后端未记录）时显示占位符。 */
function MaskedValue({ value, label }: { value: string | null; label: string }) {
  const [visible, setVisible] = useState(false)
  if (!value) return <span className="chenxing-body text-sm text-[var(--chenxing-muted-foreground)]">—</span>
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      <span className="chenxing-mono min-w-0 break-all text-sm">{visible ? value : '••••••••'}</span>
      <button
        type="button"
        className="shrink-0 text-[var(--chenxing-muted-foreground)] transition-colors hover:text-[var(--chenxing-cyan)]"
        aria-label={`${visible ? '隐藏' : '显示'}${label}`}
        aria-pressed={visible}
        onClick={() => setVisible((current) => !current)}
      >
        <Icon name={visible ? 'eye-off' : 'eye'} size={14} />
      </button>
    </span>
  )
}

function DetailField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="chenxing-caption uppercase tracking-[0.08em]">{label}</p>
      <div className="mt-1.5">{children}</div>
    </div>
  )
}

type DetailState =
  | { kind: 'loading' }
  | { kind: 'ready'; data: SecurityEventDetail }
  | { kind: 'error'; message: string }

function DetailSection({ icon, title, children }: { icon: string; title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="chenxing-h3 mb-4 flex items-center gap-2">
        <Icon name={icon} className="text-[var(--chenxing-cyan)]" size={16} />{title}
      </h3>
      <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2">{children}</div>
    </section>
  )
}

/** 安全日志行详情：与审计等其它表格一致，统一以右侧抽屉呈现。 */
export function SecurityLogDetailDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const [state, setState] = useState<DetailState>({ kind: 'loading' })

  useEffect(() => {
    let active = true
    setState({ kind: 'loading' })
    void apiFetch<SecurityEventDetail>(`/api/v1/auth/security-events/${id}`)
      .then((data) => { if (active) setState({ kind: 'ready', data }) })
      .catch((reason: unknown) => {
        if (!active) return
        if (reason instanceof ApiError && reason.status === 404) {
          setState({ kind: 'error', message: '日志记录不存在或已失效。' })
          return
        }
        setState({ kind: 'error', message: reason instanceof Error ? reason.message : '日志详情加载失败。' })
      })
    return () => { active = false }
  }, [id])

  const event = state.kind === 'ready' ? state.data : null
  return (
    <Drawer
      title="日志详情"
      description={`授权记录 #${id}`}
      onClose={onClose}
      onSubmit={(submitEvent) => submitEvent.preventDefault()}
      footer={<Button type="button" onClick={onClose}>关闭</Button>}
    >
      {state.kind === 'loading' ? <Notice tone="info">正在加载日志详情…</Notice> : null}
      {state.kind === 'error' ? <Notice tone="warning">{state.message}</Notice> : null}
      {event ? (
        <div className="space-y-6">
          <DetailSection icon="shield-check" title="事件信息">
            <DetailField label="操作"><ActionBadge action={event.action} /></DetailField>
            <DetailField label="时间"><span className="chenxing-mono text-sm">{formatDate(event.created_at)}</span></DetailField>
            <DetailField label="Ray ID"><MaskedValue value={event.ray_id} label="Ray ID" /></DetailField>
            <DetailField label="IP"><MaskedValue value={event.ip} label="IP 地址" /></DetailField>
            <DetailField label="位置">
              {event.ip_location
                ? <span className="chenxing-body text-sm">{event.ip_location}</span>
                : <span className="chenxing-body text-sm text-[var(--chenxing-muted-foreground)]">—</span>}
            </DetailField>
            <DetailField label="User Agent"><MaskedValue value={event.user_agent} label="User Agent" /></DetailField>
          </DetailSection>
          {event.client ? (
            <DetailSection icon="box" title="应用信息">
              <DetailField label="应用名称"><span className="chenxing-body text-sm font-semibold">{event.client.client_name}</span></DetailField>
              <DetailField label="Client ID"><span className="chenxing-mono break-all text-sm">{event.client.client_id}</span></DetailField>
              <DetailField label="应用状态">
                {event.client.status === 'active'
                  ? <Badge tone="success">有效</Badge>
                  : <Badge tone="warning">{event.client.status || '未知'}</Badge>}
              </DetailField>
              <DetailField label="创建时间"><span className="chenxing-mono text-sm">{formatDate(event.client.created_at)}</span></DetailField>
            </DetailSection>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  )
}
