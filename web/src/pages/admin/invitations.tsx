import { useEffect, useState } from 'react'
import {
  apiFetch,
  type CreatedInvitationCode,
  type CreatedWalletRedemptionCard,
  type InvitationCodeSummary,
  type WalletRedemptionCardSummary,
} from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Button, Icon, Notice, PageIntro } from '../../components/ui'
import { TablePanel } from '../../components/data-table'
import { AdminGate, useAdminAccess } from './shared'
import { InvitationCodesTable } from './invitations/codes-table'
import { WalletCardsTable } from './invitations/cards-table'
import { CreatedPlaintext } from './invitations/created-plaintext'
import { InvitationDetailDrawer } from './invitations/detail-drawer'
import { GenerateInvitationDrawer } from './invitations/generate-invitation-drawer'
import { GenerateWalletCardDrawer } from './invitations/generate-wallet-card-drawer'
import { WalletDetailDrawer } from './invitations/wallet-detail-drawer'
import {
  downloadCsv,
  invitationListCsvRows,
  invitationPlaintextCsvRows,
  walletListCsvRows,
  walletPlaintextCsvRows,
} from './invitations/helpers'

const CODES_PATH = '/api/v1/admin/registration-invitation-codes'
const CARDS_PATH = '/api/v1/admin/wallet/redemption-codes'

type ListTab = 'codes' | 'cards'
type GenerateDrawer = 'invite' | 'wallet' | null

export function AdminInvitations() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <AdminGate access={access} permission="manage_settings">
        <InvitationsWorkspace />
      </AdminGate>
    </ConsoleLayout>
  )
}

export function InvitationsWorkspace() {
  const [tab, setTab] = useState<ListTab>('codes')
  const [generate, setGenerate] = useState<GenerateDrawer>(null)
  const [codes, setCodes] = useState<InvitationCodeSummary[] | null>(null)
  const [cards, setCards] = useState<WalletRedemptionCardSummary[] | null>(null)
  const [createdCodes, setCreatedCodes] = useState<CreatedInvitationCode[]>([])
  const [createdCards, setCreatedCards] = useState<CreatedWalletRedemptionCard[]>([])
  const [disablingCodeId, setDisablingCodeId] = useState<number | null>(null)
  const [disablingCardId, setDisablingCardId] = useState<number | null>(null)
  const [message, setMessage] = useState('')
  const [inviteDetailId, setInviteDetailId] = useState<number | null>(null)
  const [walletDetailId, setWalletDetailId] = useState<number | null>(null)

  async function loadCodes() {
    try {
      const value = await apiFetch<InvitationCodeSummary[]>(CODES_PATH)
      setCodes(Array.isArray(value) ? value : [])
    } catch (reason) {
      setCodes([])
      setMessage(reason instanceof Error ? reason.message : '邀请码列表加载失败。')
    }
  }

  async function loadCards() {
    try {
      const value = await apiFetch<WalletRedemptionCardSummary[]>(CARDS_PATH)
      setCards(Array.isArray(value) ? value : [])
    } catch (reason) {
      setCards([])
      setMessage(reason instanceof Error ? reason.message : '兑换卡列表加载失败。')
    }
  }

  useEffect(() => {
    void loadCodes()
  }, [])

  function selectTab(next: ListTab) {
    if (next === tab) return
    setTab(next)
    setMessage('')
    if (next === 'cards' && cards === null) void loadCards()
    if (next === 'codes' && codes === null) void loadCodes()
  }

  function openGenerate(kind: 'invite' | 'wallet') {
    setInviteDetailId(null)
    setWalletDetailId(null)
    setMessage('')
    setGenerate(kind)
  }

  function handleInviteCreated(created: CreatedInvitationCode[]) {
    setCreatedCodes(created)
    setGenerate(null)
    setTab('codes')
    setMessage('')
    void loadCodes()
  }

  function handleWalletCreated(created: CreatedWalletRedemptionCard[]) {
    setCreatedCards(created)
    setGenerate(null)
    setTab('cards')
    setMessage('')
    void loadCards()
  }

  async function disableCode(id: number) {
    if (!window.confirm('确认停用这个邀请码吗？停用后不可恢复。')) return
    setDisablingCodeId(id)
    setMessage('')
    try {
      await apiFetch(`${CODES_PATH}/${id}/disable`, { method: 'POST' })
      await loadCodes()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '邀请码停用失败。')
    } finally {
      setDisablingCodeId(null)
    }
  }

  async function disableCard(id: number) {
    if (!window.confirm('确认停用这张兑换卡吗？停用后不可恢复。')) return
    setDisablingCardId(id)
    setMessage('')
    try {
      await apiFetch(`${CARDS_PATH}/${id}/disable`, { method: 'POST' })
      await loadCards()
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '兑换卡停用失败。')
    } finally {
      setDisablingCardId(null)
    }
  }

  async function copyPlaintext(values: string[]) {
    try {
      if (!navigator.clipboard) throw new Error('clipboard unavailable')
      await navigator.clipboard.writeText(values.join('\n'))
    } catch {
      setMessage('复制失败，请手动选择明文。')
    }
  }

  function exportList() {
    if (tab === 'codes') {
      if (!codes?.length) return
      downloadCsv('invitation-codes.csv', invitationListCsvRows(codes))
      return
    }
    if (!cards?.length) return
    downloadCsv('wallet-redemption-cards.csv', walletListCsvRows(cards))
  }

  const listReady = tab === 'codes' ? Boolean(codes?.length) : Boolean(cards?.length)

  return (
    <>
      <PageIntro
        eyebrow="// Admin · Invitations"
        title="邀请与兑换"
        description="生成注册邀请码和辰星点兑换卡。明文只在生成后展示一次。"
        action={
          <div className="flex flex-wrap items-center gap-3">
            <Button icon="ticket" onClick={() => openGenerate('invite')}>生成邀请码</Button>
            <Button variant="ghost" icon="wallet" onClick={() => openGenerate('wallet')}>生成兑换卡</Button>
          </div>
        }
      />
      <div className="flex flex-col gap-6">
        {message ? <Notice tone="warning">{message}</Notice> : null}
        {tab === 'codes' ? (
          <CreatedPlaintext
            kind="invitation"
            items={createdCodes}
            onCopyAll={() => void copyPlaintext(createdCodes.map((item) => item.code))}
            onExport={() => downloadCsv('invitation-codes-plaintext.csv', invitationPlaintextCsvRows(createdCodes))}
          />
        ) : (
          <CreatedPlaintext
            kind="wallet"
            items={createdCards}
            onCopyAll={() => void copyPlaintext(createdCards.map((item) => item.code))}
            onExport={() => downloadCsv('wallet-redemption-cards-plaintext.csv', walletPlaintextCsvRows(createdCards))}
          />
        )}
        <TablePanel
          icon={tab === 'codes' ? 'ticket' : 'wallet'}
          title={tab === 'codes' ? '邀请码列表' : '兑换卡列表'}
          description="列表不包含明文。点击一行可查看使用明细。"
          action={
            <Button variant="ghost" icon="download" onClick={exportList} disabled={!listReady}>
              导出列表 CSV
            </Button>
          }
        >
          <div
            className="mt-5 grid grid-cols-2 gap-1 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.5)] p-1"
            role="tablist"
            aria-label="邀请与兑换"
          >
            <ListTabButton tab="codes" activeTab={tab} icon="ticket" label="邀请码" onSelect={selectTab} />
            <ListTabButton tab="cards" activeTab={tab} icon="wallet" label="兑换卡" onSelect={selectTab} />
          </div>
          {tab === 'codes' ? (
            <div id="invitations-codes-panel" role="tabpanel" aria-labelledby="invitations-codes-tab">
              <InvitationCodesTable
                codes={codes}
                busyId={disablingCodeId}
                onDisable={(id) => void disableCode(id)}
                onOpen={(item) => { setGenerate(null); setWalletDetailId(null); setInviteDetailId(item.id) }}
              />
            </div>
          ) : (
            <div id="invitations-cards-panel" role="tabpanel" aria-labelledby="invitations-cards-tab">
              <WalletCardsTable
                cards={cards}
                busyId={disablingCardId}
                onDisable={(id) => void disableCard(id)}
                onOpen={(item) => { setGenerate(null); setInviteDetailId(null); setWalletDetailId(item.id) }}
              />
            </div>
          )}
        </TablePanel>
      </div>
      {generate === 'invite' ? (
        <GenerateInvitationDrawer onClose={() => setGenerate(null)} onCreated={handleInviteCreated} />
      ) : null}
      {generate === 'wallet' ? (
        <GenerateWalletCardDrawer onClose={() => setGenerate(null)} onCreated={handleWalletCreated} />
      ) : null}
      {inviteDetailId != null ? (
        <InvitationDetailDrawer codeId={inviteDetailId} onClose={() => setInviteDetailId(null)} />
      ) : null}
      {walletDetailId != null ? (
        <WalletDetailDrawer cardId={walletDetailId} onClose={() => setWalletDetailId(null)} />
      ) : null}
    </>
  )
}

function ListTabButton({ tab, activeTab, icon, label, onSelect }: {
  tab: ListTab
  activeTab: ListTab
  icon: string
  label: string
  onSelect: (tab: ListTab) => void
}) {
  const selected = activeTab === tab
  const tabId = tab === 'codes' ? 'invitations-codes-tab' : 'invitations-cards-tab'
  const panelId = tab === 'codes' ? 'invitations-codes-panel' : 'invitations-cards-panel'
  return (
    <button
      id={tabId}
      type="button"
      role="tab"
      aria-selected={selected}
      aria-controls={panelId}
      tabIndex={selected ? 0 : -1}
      className={`flex min-h-11 items-center justify-center gap-2 rounded-[calc(var(--chenxing-radius-md)-2px)] px-3 text-sm font-semibold transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--chenxing-cyan)] ${selected ? 'bg-[var(--chenxing-muted)] text-[var(--chenxing-foreground)] shadow-[inset_0_0_0_1px_var(--chenxing-border-strong)]' : 'text-[var(--chenxing-muted-foreground)] hover:bg-[rgba(255,255,255,0.04)] hover:text-[var(--chenxing-foreground)]'}`}
      onClick={() => onSelect(tab)}
    >
      <Icon name={icon} size={16} className={selected ? 'text-[var(--chenxing-cyan)]' : ''} />
      {label}
    </button>
  )
}
