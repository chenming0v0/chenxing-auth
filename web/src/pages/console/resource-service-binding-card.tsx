import type { ReactNode } from 'react'
import { Badge, Button, HudPanel } from '@chenxing/ui'
import type { ResourceServiceBinding, ResourceServiceSnapshotField } from '../../resource-services-types'
import { parseResourceServiceSnapshot } from '../../resource-services-types'
import {
  formatDuration,
  statusPresentation,
  subscriptionSummary,
  visibleSnapshotFields,
} from '../../resource-services-snapshot'
import { formatDate } from '../../data'

type Props = {
  binding: ResourceServiceBinding
  providerName: string
  busy: boolean
  pending: boolean
  onSync: () => void
  onRefresh: () => void
  onUnlink: () => void
}

function FieldValue({ field }: { field: ResourceServiceSnapshotField }) {
  switch (field.type) {
    case 'boolean':
      return <>{field.value ? '是' : '否'}</>
    case 'datetime':
      return <>{formatDate(field.value)}</>
    case 'duration':
      return <>{formatDuration(field.value)}</>
    case 'status': {
      const status = statusPresentation(field.value)
      return <Badge tone={status.tone}>{status.label}</Badge>
    }
    case 'url':
      return <a className="chenxing-link break-all" href={field.value} target="_blank" rel="noreferrer noopener">{field.value}</a>
    case 'number':
      return <>{String(field.value)}</>
    case 'text':
      return <>{field.value}</>
  }
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="chenxing-caption">{label}</dt>
      <dd className="chenxing-body mt-0.5 break-all">{children}</dd>
    </div>
  )
}

export function ResourceServiceBindingCard({ binding, providerName, busy, pending, onSync, onRefresh, onUnlink }: Props) {
  const snapshot = parseResourceServiceSnapshot(binding.snapshot)
  const status = statusPresentation(binding.status ?? snapshot?.status ?? null)
  const subscription = snapshot?.subscription ? subscriptionSummary(snapshot.subscription, new Date()) : null
  const fields = visibleSnapshotFields(snapshot?.fields ?? [], subscription !== null)
  const displayName = binding.name ?? snapshot?.name ?? null
  // 头部展示提供方给出的展示账号；顶层 uid 是绑定键，不作为「UID」展示。
  // 提供方想展示什么 UID，由它自己在 fields[] 里用 uid 字段和 label 决定。
  const account = binding.account ?? snapshot?.account ?? binding.uid

  return (
    <HudPanel as="article" className="!p-5 sm:!p-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="chenxing-h3">{providerName}</h2>
            <Badge tone={status.tone}>{status.label}</Badge>
          </div>
          {displayName ? <p className="chenxing-body mt-1">{displayName}</p> : null}
          <p className="chenxing-caption mt-1 flex flex-wrap items-baseline gap-x-2">
            <span>账号</span>
            <span className="chenxing-mono break-all">{account}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="ghost" icon="refresh-cw" disabled={busy || pending} onClick={onSync}>
            {pending ? '同步中…' : '同步'}
          </Button>
          <Button variant="ghost" disabled={busy || pending} onClick={onRefresh}>刷新令牌</Button>
          <Button variant="danger" icon="unlink" disabled={busy} onClick={onUnlink}>解绑</Button>
        </div>
      </div>

      <dl className="mt-5 grid grid-cols-1 gap-4 border-t border-[var(--chenxing-border)] pt-5 sm:grid-cols-2">
        {subscription ? (
          <Item label="订阅">
            <span className="flex flex-wrap items-center gap-2">
              <Badge tone={subscription.tone}>{subscription.label}</Badge>
              {subscription.expiresAt ? <span className="chenxing-caption">到期 {formatDate(subscription.expiresAt)}</span> : null}
            </span>
          </Item>
        ) : null}
        {fields.map((field, index) => (
          <Item key={`${index}:${field.key}`} label={field.label}><FieldValue field={field} /></Item>
        ))}
        {snapshot?.fetched_at ? <Item label="最近同步">{formatDate(snapshot.fetched_at)}</Item> : null}
      </dl>

      <dl className="mt-4 border-t border-[var(--chenxing-border)] pt-4">
        <Item label="授权到期">
          {formatDate(binding.grant_expires_at)}
          <span className="chenxing-caption mt-0.5 block">辰星对该账号的只读授权期限，与订阅到期无关。</span>
        </Item>
      </dl>
    </HudPanel>
  )
}
