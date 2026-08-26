import type { InvitationCodeSummary } from '../../../api'
import { Badge, Button, EmptyState } from '../../../components/ui'
import { DataTable, TablePanel } from '../../../components/data-table'
import { formatDate } from '../../../data'
import { invitationStatus, invitationStatusTone } from './helpers'

type Props = {
  codes: InvitationCodeSummary[] | null
  busyId: number | null
  onDisable: (id: number) => void
  onOpen: (item: InvitationCodeSummary) => void
  onExport: () => void
}

export function InvitationCodesTable({ codes, busyId, onDisable, onOpen, onExport }: Props) {
  return (
    <TablePanel
      icon="ticket"
      title="邀请码列表"
      description="列表不包含明文。点击一行可查看使用明细。"
      action={
        <Button variant="ghost" icon="download" onClick={onExport} disabled={!codes?.length}>
          导出列表 CSV
        </Button>
      }
    >
      <DataTable
        minWidth={880}
        columns={['ID', '标签', '已用/上限', '状态', '创建时间', { label: '操作', align: 'right' }]}
        empty={codes == null ? '正在加载邀请码。' : codes.length ? null : (
          <EmptyState icon="ticket" title="还没有邀请码" description="生成一批邀请码后，会显示在这里。" />
        )}
      >
        {codes?.map((item) => {
          const status = invitationStatus(item)
          return (
            <tr
              key={item.id}
              className="cursor-pointer"
              onClick={() => onOpen(item)}
            >
              <td className="chenxing-mono text-xs">#{item.id}</td>
              <td className="chenxing-body text-sm">{item.label || '—'}</td>
              <td className="chenxing-mono text-xs">{item.use_count}/{item.max_uses}</td>
              <td><Badge tone={invitationStatusTone(status)}>{status}</Badge></td>
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
    </TablePanel>
  )
}
