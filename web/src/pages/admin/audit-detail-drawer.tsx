import type { ReactNode } from 'react'
import type { AuditEvent } from '../../api'
import { Drawer } from '../../components/drawer'
import { Button } from '../../components/ui'
import { formatDate } from '../../data'
import { ActionBadge, lookupAction, resourceLabel, SeverityBadge, formatActor } from './audit-labels'

function hasMetadata(metadata: Record<string, unknown> | undefined): boolean {
  return Boolean(metadata && Object.keys(metadata).length > 0)
}

function DetailField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <p className="chenxing-caption uppercase tracking-[0.08em]">{label}</p>
      <div className="mt-1.5">{children}</div>
    </div>
  )
}

export function AuditDetailDrawer({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const action = event.action || ''
  const known = lookupAction(action)
  const title = known?.label || action || '审计事件'
  const resource = resourceLabel(event.resource_type)

  return (
    <Drawer
      title={title}
      description={formatDate(event.created_at)}
      onClose={onClose}
      onSubmit={(submitEvent) => submitEvent.preventDefault()}
      footer={<Button type="button" onClick={onClose}>关闭</Button>}
    >
      <div className="grid gap-4 sm:grid-cols-2">
        <DetailField label="事件">
          <div className="flex flex-wrap items-center gap-2">
            <ActionBadge action={action} />
            {known && action ? <span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{action}</span> : null}
          </div>
        </DetailField>
        <DetailField label="级别"><SeverityBadge action={action} /></DetailField>
        <DetailField label="执行者">
          <p className="chenxing-body text-sm">{formatActor(event.actor_type, event.actor_id)}</p>
        </DetailField>
        <DetailField label="资源">
          <p className="chenxing-body text-sm">{resource}</p>
          {event.resource_id ? <p className="chenxing-caption chenxing-mono mt-0.5">{event.resource_id}</p> : null}
        </DetailField>
        <DetailField label="时间">
          <p className="chenxing-mono text-sm">{formatDate(event.created_at)}</p>
        </DetailField>
      </div>
      <div className="mt-5">
        <p className="chenxing-caption uppercase tracking-[0.08em]">附加详情</p>
        {hasMetadata(event.metadata) ? (
          <pre className="chenxing-mono mt-1.5 max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] p-3 text-xs text-[var(--chenxing-ice)]">
            {JSON.stringify(event.metadata, null, 2)}
          </pre>
        ) : (
          <p className="chenxing-caption mt-1.5">没有附加详情</p>
        )}
      </div>
    </Drawer>
  )
}
