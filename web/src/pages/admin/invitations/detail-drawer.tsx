import { useEffect, useState } from 'react'
import { apiFetch, type InvitationCodeDetail } from '../../../api'
import { Drawer } from '@chenxing/ui'
import { Button, EmptyState, Notice } from '@chenxing/ui'
import { DataTable } from '@chenxing/ui'
import { formatDate } from '../../../data'

export function InvitationDetailDrawer({ codeId, onClose }: { codeId: number; onClose: () => void }) {
  const [detail, setDetail] = useState<InvitationCodeDetail | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    setError('')
    void apiFetch<InvitationCodeDetail>(`/api/v1/admin/registration-invitation-codes/${codeId}`)
      .then((value) => { if (active) setDetail(value) })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : '邀请码明细加载失败。')
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [codeId])

  const title = detail?.label ? `邀请码 · ${detail.label}` : `邀请码 #${codeId}`
  const description = detail
    ? `已用 ${detail.use_count} / ${detail.max_uses}`
    : '查看这个邀请码被哪些账号使用过。'

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
        <EmptyState icon="ticket" title="还没有人使用这个邀请码" />
      ) : null}
      {detail && detail.uses.length > 0 ? (
        <DataTable columns={['用户', '用户 ID', '使用时间']} minWidth={480}>
          {detail.uses.map((use) => (
            <tr key={`${use.user_id}-${use.used_at}`}>
              <td>
                <p className="chenxing-body text-sm">{use.display_name || use.username}</p>
                {use.display_name ? (
                  <p className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{use.username}</p>
                ) : null}
              </td>
              <td className="chenxing-mono text-xs">{use.user_id}</td>
              <td className="chenxing-caption">{formatDate(use.used_at)}</td>
            </tr>
          ))}
        </DataTable>
      ) : null}
    </Drawer>
  )
}
