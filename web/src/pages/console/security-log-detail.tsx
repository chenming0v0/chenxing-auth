import { useEffect, useState } from 'react'
import { Link } from '../../router'
import { ApiError, apiFetch, type SecurityEventDetail } from '../../api'
import { Badge, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
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

export function SecurityLogDetail({ id }: { id: number }) {
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

  const back = (
    <Link className="chenxing-btn-ghost" to="/console/logs"><Icon name="arrow-left" size={16} />返回</Link>
  )

  if (state.kind !== 'ready') {
    return (
      <>
        <PageIntro eyebrow="// Security · Log Detail" title="日志详情" description={`授权记录 #${id}`} action={back} />
        {state.kind === 'loading'
          ? <Notice tone="info">正在加载日志详情…</Notice>
          : <Notice tone="warning">{state.message}</Notice>}
      </>
    )
  }

  const event = state.data
  return (
    <>
      <PageIntro eyebrow="// Security · Log Detail" title="日志详情" description={`授权记录 #${event.id}`} action={back} />
      <div className="space-y-6">
        <HudPanel>
          <h2 className="chenxing-h2 mb-5 flex items-center gap-2">
            <Icon name="shield-check" className="text-[var(--chenxing-cyan)]" size={18} />事件信息
          </h2>
          <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
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
          </div>
        </HudPanel>
        {event.client ? (
          <HudPanel>
            <h2 className="chenxing-h2 mb-5 flex items-center gap-2">
              <Icon name="box" className="text-[var(--chenxing-cyan)]" size={18} />应用信息
            </h2>
            <div className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
              <DetailField label="应用名称"><span className="chenxing-body text-sm font-semibold">{event.client.client_name}</span></DetailField>
              <DetailField label="Client ID"><span className="chenxing-mono break-all text-sm">{event.client.client_id}</span></DetailField>
              <DetailField label="应用状态">
                {event.client.status === 'active'
                  ? <Badge tone="success">有效</Badge>
                  : <Badge tone="warning">{event.client.status || '未知'}</Badge>}
              </DetailField>
              <DetailField label="创建时间"><span className="chenxing-mono text-sm">{formatDate(event.client.created_at)}</span></DetailField>
            </div>
          </HudPanel>
        ) : null}
      </div>
    </>
  )
}
