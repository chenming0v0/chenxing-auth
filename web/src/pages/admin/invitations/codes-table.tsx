import type { InvitationCodeSummary } from '../../../api'
import { Badge, EmptyState } from '@chenxing/ui'
import { DataTable, RowAction, RowActions } from '@chenxing/ui'
import { formatDate } from '../../../data'
import { issuanceStatus, issuanceStatusTone } from './helpers'

type Props = {
  codes: InvitationCodeSummary[] | null
  busyId: number | null
  onDisable: (id: number) => void
  onOpen: (item: InvitationCodeSummary) => void
}

export function InvitationCodesTable({ codes, busyId, onDisable, onOpen }: Props) {
  return (
    <DataTable
      minWidth={880}
      columns={['ID', '标签', '已用/上限', '状态', '创建时间', { label: '操作', align: 'right' }]}
      empty={codes == null ? '正在加载邀请码。' : codes.length ? null : (
        <EmptyState icon="ticket" title="还没有邀请码" description="生成一批邀请码后，会显示在这里。" />
      )}
    >
      {codes?.map((item) => {
        const status = issuanceStatus(item)
        return (
          <tr
            key={item.id}
            className="cursor-pointer"
            onClick={() => onOpen(item)}
          >
            <td className="chenxing-mono text-xs">#{item.id}</td>
            <td className="chenxing-body text-sm">{item.label || '—'}</td>
            <td className="chenxing-mono text-xs">{item.use_count}/{item.max_uses}</td>
            <td><Badge tone={issuanceStatusTone(status)}>{status}</Badge></td>
            <td className="chenxing-caption">{formatDate(item.created_at)}</td>
            <RowActions>
              <RowAction
                tone="danger"
                disabled={busyId === item.id || Boolean(item.disabled_at)}
                onClick={() => onDisable(item.id)}
              >
                停用
              </RowAction>
            </RowActions>
          </tr>
        )
      })}
    </DataTable>
  )
}
