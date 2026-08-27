import { Button, CopyValue, HudPanel, Notice } from '@chenxing/ui'

type PlaintextItem = { id: number; code: string }

export function CreatedPlaintext({
  kind,
  items,
  onCopyAll,
  onExport,
}: {
  kind: 'invitation' | 'wallet'
  items: PlaintextItem[]
  onCopyAll: () => void
  onExport: () => void
}) {
  if (!items.length) return null
  const noun = kind === 'invitation' ? '邀请码' : '兑换码'
  return (
    <HudPanel>
      <Notice tone="warning">请立即保存以下{noun}，离开后无法再次查看明文。</Notice>
      <div className="mt-4 flex flex-wrap gap-3">
        <Button icon="copy" onClick={onCopyAll}>复制全部</Button>
        <Button variant="ghost" icon="download" onClick={onExport}>导出 CSV（明文，仅此次）</Button>
      </div>
      <div className="mt-4 space-y-2">
        {items.map((item) => (
          <CopyValue key={item.id} value={item.code} ariaLabel={`复制${noun} ${item.id}`} />
        ))}
      </div>
    </HudPanel>
  )
}
