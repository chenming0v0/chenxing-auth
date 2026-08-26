import type { FormEvent } from 'react'
import type { CreatedInvitationCode } from '../../../api'
import { Button, CopyValue, Field, HudPanel, Icon, Notice } from '../../../components/ui'

type GenerateProps = {
  count: string
  maxUses: string
  label: string
  expiresAt: string
  busy: boolean
  onCount: (value: string) => void
  onMaxUses: (value: string) => void
  onLabel: (value: string) => void
  onExpiresAt: (value: string) => void
  onSubmit: () => void
}

export function InvitationGeneratePanel({
  count, maxUses, label, expiresAt, busy, onCount, onMaxUses, onLabel, onExpiresAt, onSubmit,
}: GenerateProps) {
  function submit(event: FormEvent) {
    event.preventDefault()
    onSubmit()
  }

  return (
    <HudPanel>
      <form onSubmit={submit}>
        <h2 className="chenxing-h2 flex items-center gap-2">
          <Icon name="ticket" className="text-[var(--chenxing-cyan)]" size={18} />
          生成邀请码
        </h2>
        <p className="chenxing-caption mt-1.5">明文只在生成后展示一次，请立即保存。</p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <Field label="生成数量" type="number" min="1" max="100" value={count} onChange={(event) => onCount(event.target.value)} />
          <Field label="每码可用次数" type="number" min="1" max="10000" value={maxUses} onChange={(event) => onMaxUses(event.target.value)} />
          <Field label="标签" value={label} onChange={(event) => onLabel(event.target.value)} placeholder="可选" />
          <Field label="过期时间" type="datetime-local" value={expiresAt} onChange={(event) => onExpiresAt(event.target.value)} />
        </div>
        <div className="mt-4">
          <Button type="submit" icon="plus" disabled={busy}>批量生成</Button>
        </div>
      </form>
    </HudPanel>
  )
}

export function CreatedInvitationCodes({
  codes, onCopyAll, onExport,
}: {
  codes: CreatedInvitationCode[]
  onCopyAll: () => void
  onExport: () => void
}) {
  if (!codes.length) return null
  return (
    <HudPanel>
      <Notice tone="warning">请立即保存以下邀请码，离开后无法再次查看明文。</Notice>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button icon="copy" onClick={onCopyAll}>复制全部</Button>
        <Button variant="ghost" icon="download" onClick={onExport}>导出 CSV（明文，仅此次）</Button>
      </div>
      <div className="mt-4 space-y-2">
        {codes.map((item) => (
          <CopyValue key={item.id} value={item.code} ariaLabel={`复制邀请码 ${item.id}`} />
        ))}
      </div>
    </HudPanel>
  )
}
