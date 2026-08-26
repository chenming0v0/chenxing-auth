import { useEffect, useState } from 'react'
import { apiFetch, type CreatedInvitationCode, type InvitationCodeSummary } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Notice, PageIntro } from '../../components/ui'
import { AdminGate, useAdminAccess } from './shared'
import { validateIntegerWithinRange } from './settings/panel'
import { InvitationCodesTable } from './invitations/codes-table'
import { InvitationDetailDrawer } from './invitations/detail-drawer'
import { CreatedInvitationCodes, InvitationGeneratePanel } from './invitations/generate-panel'
import { downloadCsv, invitationListCsvRows, invitationPlaintextCsvRows } from './invitations/helpers'
import { WalletCardsPanel } from './invitations/wallet-cards-panel'

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'

export function AdminInvitations() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Admin · Invitations"
        title="注册邀请码"
        description="生成和管理注册邀请码。明文只在生成后展示一次，之后只能查看使用状态。"
      />
      <AdminGate access={access} permission="manage_settings">
        <div className="flex flex-col gap-10">
          <InvitationsWorkspace />
          <section aria-labelledby="wallet-redemption-heading">
            <div className="mb-4"><h2 id="wallet-redemption-heading" className="chenxing-h2">钱包兑换卡</h2><p className="chenxing-caption mt-1">发放辰星点兑换码，并管理其有效状态。</p></div>
            <WalletCardsPanel />
          </section>
        </div>
      </AdminGate>
    </ConsoleLayout>
  )
}

export function InvitationsWorkspace() {
  const [codes, setCodes] = useState<InvitationCodeSummary[] | null>(null)
  const [created, setCreated] = useState<CreatedInvitationCode[]>([])
  const [count, setCount] = useState('1')
  const [maxUses, setMaxUses] = useState('1')
  const [label, setLabel] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [busy, setBusy] = useState(false)
  const [disablingId, setDisablingId] = useState<number | null>(null)
  const [message, setMessage] = useState('')
  const [detailId, setDetailId] = useState<number | null>(null)

  async function load() {
    const value = await apiFetch<InvitationCodeSummary[]>(CODES_PATH)
    setCodes(Array.isArray(value) ? value : [])
  }

  useEffect(() => {
    void load().catch((reason: unknown) => {
      setCodes([])
      setMessage(reason instanceof Error ? reason.message : '邀请码列表加载失败。')
    })
  }, [])

  async function create() {
    const countResult = validateIntegerWithinRange(count, '生成数量', 100)
    if ('error' in countResult) { setMessage(countResult.error); return }
    const usesResult = validateIntegerWithinRange(maxUses, '每码可用次数', 10000)
    if ('error' in usesResult) { setMessage(usesResult.error); return }
    let expires: string | null = null
    if (expiresAt.trim()) {
      const date = new Date(expiresAt)
      if (Number.isNaN(date.valueOf())) { setMessage('过期时间格式无效。'); return }
      expires = date.toISOString()
    }
    setBusy(true)
    setMessage('')
    try {
      const value = await apiFetch<CreatedInvitationCode[]>(CODES_PATH, {
        method: 'POST',
        body: JSON.stringify({
          count: countResult.value,
          max_uses: usesResult.value,
          expires_at: expires,
          label: label.trim() || null,
        }),
      })
      setCreated(Array.isArray(value) ? value : [])
      await load()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '邀请码生成失败。')
    } finally {
      setBusy(false)
    }
  }

  async function disable(id: number) {
    if (!window.confirm('确认停用这个邀请码吗？停用后不可恢复。')) return
    setDisablingId(id)
    setMessage('')
    try {
      await apiFetch(`${CODES_PATH}/${id}/disable`, { method: 'POST' })
      await load()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '邀请码停用失败。')
    } finally {
      setDisablingId(null)
    }
  }

  async function copyCreated() {
    const text = created.map((item) => item.code).join('\n')
    try {
      if (!navigator.clipboard) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(text)
    } catch {
      setMessage('复制失败，请手动选择明文。')
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {message ? <Notice tone="warning">{message}</Notice> : null}
      <InvitationGeneratePanel
        count={count}
        maxUses={maxUses}
        label={label}
        expiresAt={expiresAt}
        busy={busy}
        onCount={setCount}
        onMaxUses={setMaxUses}
        onLabel={setLabel}
        onExpiresAt={setExpiresAt}
        onSubmit={() => void create()}
      />
      <CreatedInvitationCodes
        codes={created}
        onCopyAll={() => void copyCreated()}
        onExport={() => downloadCsv('invitation-codes-plaintext.csv', invitationPlaintextCsvRows(created))}
      />
      <InvitationCodesTable
        codes={codes}
        busyId={disablingId}
        onDisable={(id) => void disable(id)}
        onOpen={(item) => setDetailId(item.id)}
        onExport={() => {
          if (!codes?.length) return
          downloadCsv('invitation-codes.csv', invitationListCsvRows(codes))
        }}
      />
      {detailId != null ? <InvitationDetailDrawer codeId={detailId} onClose={() => setDetailId(null)} /> : null}
    </div>
  )
}
