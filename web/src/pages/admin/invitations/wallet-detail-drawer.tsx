import { useEffect, useState } from 'react'
import { apiFetch, type WalletRedemptionCardDetail } from '../../../api'
import { Drawer } from '@chenxing/ui'
import { Button, EmptyState, Notice } from '@chenxing/ui'
import { DataTable } from '@chenxing/ui'
import { formatDate } from '../../../data'

export function WalletDetailDrawer({ cardId, onClose }: { cardId: number; onClose: () => void }) {
  const [detail, setDetail] = useState<WalletRedemptionCardDetail | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    void apiFetch<WalletRedemptionCardDetail>(`/api/v1/admin/wallet/redemption-codes/${cardId}`)
      .then((value) => { if (active) setDetail(value) })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : '兑换卡明细加载失败。')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [cardId])

  const title = detail?.label ? `兑换卡 · ${detail.label}` : `兑换卡 #${cardId}`
  const description = detail
    ? `已用 ${detail.use_count} / ${detail.max_uses} · 面值 ${detail.points.toLocaleString('zh-CN')} 点`
    : '查看这张兑换卡被哪些账号使用过。'

  return (
    <Drawer
      title={title}
      description={description}
      onClose={onClose}
      onSubmit={(event) => event.preventDefault()}
      footer={<Button type="button" onClick={onClose}>关闭</Button>}
    >
      {error ? <Notice tone="warning">{error}</Notice> : null}
      {loading && !detail ? <p className="chenxing-caption">正在加载使用明细。</p> : null}
      {detail && detail.uses.length === 0 ? (
        <EmptyState icon="wallet" title="还没有人使用这张兑换卡" />
      ) : null}
      {detail && detail.uses.length > 0 ? (
        <DataTable columns={['用户', '用户 ID', '面值', '兑换时间']} minWidth={520}>
          {detail.uses.map((use) => (
            <tr key={`${use.user_id}-${use.redeemed_at}`}>
              <td>
                <p className="chenxing-body text-sm">{use.display_name || use.username}</p>
                {use.display_name ? (
                  <p className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{use.username}</p>
                ) : null}
              </td>
              <td className="chenxing-mono text-xs">{use.user_id}</td>
              <td className="chenxing-mono text-xs">{use.points.toLocaleString('zh-CN')} 点</td>
              <td className="chenxing-caption">{formatDate(use.redeemed_at)}</td>
            </tr>
          ))}
        </DataTable>
      ) : null}
    </Drawer>
  )
}
