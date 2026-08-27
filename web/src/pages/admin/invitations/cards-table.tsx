import type { WalletRedemptionCardSummary } from '../../../api'
import { Badge, Button, EmptyState } from '@chenxing/ui'
import { DataTable } from '@chenxing/ui'
import { formatDate } from '../../../data'
import { issuanceStatus, issuanceStatusTone } from './helpers'

type Props = {
  cards: WalletRedemptionCardSummary[] | null
  busyId: number | null
  onDisable: (id: number) => void
  onOpen: (item: WalletRedemptionCardSummary) => void
}

export function WalletCardsTable({ cards, busyId, onDisable, onOpen }: Props) {
  return (
    <DataTable
      minWidth={920}
      columns={['ID', '标签', '面值', '已用/上限', '状态', '创建时间', { label: '操作', align: 'right' }]}
      empty={cards == null ? '正在加载兑换卡。' : cards.length ? null : (
        <EmptyState icon="wallet" title="还没有兑换卡" description="生成一批兑换卡后，会显示在这里。" />
      )}
    >
      {cards?.map((item) => {
        const status = issuanceStatus(item)
        return (
          <tr
            key={item.id}
            className="cursor-pointer"
            onClick={() => onOpen(item)}
          >
            <td className="chenxing-mono text-xs">#{item.id}</td>
            <td className="chenxing-body text-sm">{item.label || '—'}</td>
            <td className="chenxing-mono text-sm">{item.points.toLocaleString('zh-CN')} 点</td>
            <td className="chenxing-mono text-xs">{item.use_count}/{item.max_uses}</td>
            <td><Badge tone={issuanceStatusTone(status)}>{status}</Badge></td>
            <td className="chenxing-caption">{formatDate(item.created_at)}</td>
            <td className="text-right" onClick={(event) => event.stopPropagation()}>
              <Button
                variant="danger"
                disabled={busyId === item.id || Boolean(item.disabled_at)}
                onClick={() => onDisable(item.id)}
              >
                停用
              </Button>
            </td>
          </tr>
        )
      })}
    </DataTable>
  )
}
