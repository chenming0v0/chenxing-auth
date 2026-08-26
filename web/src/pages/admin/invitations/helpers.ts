import type { CreatedInvitationCode, InvitationCodeSummary } from '../../../api'

export type InvitationStatus = '可用' | '已停用' | '已用尽' | '已过期'

export function invitationStatus(item: InvitationCodeSummary): InvitationStatus {
  if (item.disabled_at) return '已停用'
  if (item.use_count >= item.max_uses) return '已用尽'
  if (item.expires_at && Date.parse(item.expires_at) <= Date.now()) return '已过期'
  return '可用'
}

export function invitationStatusTone(status: InvitationStatus): 'success' | 'warning' | 'neutral' {
  if (status === '可用') return 'success'
  if (status === '已用尽') return 'neutral'
  return 'warning'
}

function csvCell(value: string | number | null): string {
  const text = value == null ? '' : String(value)
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text
}

export function toCsv(rows: Array<Array<string | number | null>>): string {
  return rows.map((row) => row.map(csvCell).join(',')).join('\n')
}

export function downloadCsv(filename: string, rows: Array<Array<string | number | null>>) {
  const blob = new Blob([`\uFEFF${toCsv(rows)}\n`], { type: 'text/csv;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export function invitationListCsvRows(codes: InvitationCodeSummary[]): Array<Array<string | number | null>> {
  return [
    ['id', 'label', 'max_uses', 'use_count', 'status', 'expires_at', 'created_at'],
    ...codes.map((item) => [
      item.id,
      item.label,
      item.max_uses,
      item.use_count,
      invitationStatus(item),
      item.expires_at,
      item.created_at,
    ]),
  ]
}

export function invitationPlaintextCsvRows(codes: CreatedInvitationCode[]): Array<Array<string | number | null>> {
  return [
    ['id', 'label', 'code', 'max_uses', 'expires_at', 'created_at'],
    ...codes.map((item) => [item.id, item.label, item.code, item.max_uses, item.expires_at, item.created_at]),
  ]
}
