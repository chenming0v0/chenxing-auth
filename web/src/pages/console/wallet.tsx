import { useEffect, useState } from 'react'
import { apiFetch, type Paged, type WalletBalance, type WalletLedgerEntry } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, HudPanel, Notice, PageIntro } from '../../components/ui'
import { DataTable, TablePagination, TablePanel } from '../../components/data-table'
import { formatDate } from '../../data'
import { replaceUrl, useLocation } from '../../router'
import { WalletPurchaseDrawer } from './wallet-purchase-drawer'
import { WalletRedeemPanel } from './wallet-redeem-panel'
import { WalletAddonPanel } from './wallet-addon-panel'

const PAGE_SIZE = 20

const KIND_LABEL: Record<string, string> = {
  credit: '充值',
  purchase: '购买',
  adjust: '调整',
}

const KIND_TONE: Record<string, 'success' | 'gold' | 'warning' | 'neutral'> = {
  credit: 'success',
  purchase: 'gold',
  adjust: 'warning',
}

function formatPoints(value: number): string {
  return value.toLocaleString('zh-CN')
}

function formatDelta(amount: number): string {
  const abs = formatPoints(Math.abs(amount))
  if (amount > 0) return `+${abs}`
  if (amount < 0) return `-${abs}`
  return abs
}

function kindLabel(kind: string): string {
  return KIND_LABEL[kind] ?? kind
}

export function ConsoleWallet() {
  const location = useLocation()
  const purchaseRequested = new URLSearchParams(location.search).get('purchase') === '1'
  const [catalogOpen, setCatalogOpen] = useState(purchaseRequested)
  const [notice, setNotice] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)

  useEffect(() => {
    if (purchaseRequested) setCatalogOpen(true)
  }, [purchaseRequested])

  function closeCatalog() {
    setCatalogOpen(false)
    if (purchaseRequested) replaceUrl('/console/wallet')
  }

  function onPurchased() {
    closeCatalog()
    setNotice('已购买')
    setRefreshKey((value) => value + 1)
  }

  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Account · Wallet"
        title="钱包"
        description="辰星点用于购买套餐订阅。充值目前由管理员发放。"
      />
      {notice ? <div className="mb-4"><Notice tone="success">{notice}</Notice></div> : null}
      <WalletBalancePanel
        refreshKey={refreshKey}
        onPurchase={() => { setNotice(''); setCatalogOpen(true) }}
      />
      <div className="mt-6">
        <WalletRedeemPanel onRedeemed={() => { setNotice('兑换卡已到账'); setRefreshKey((value) => value + 1) }} />
      </div>
      <WalletAddonPanel onPurchased={() => { setNotice('增量包已购买'); setRefreshKey((value) => value + 1) }} />
      <WalletLedger refreshKey={refreshKey} />
      {catalogOpen ? (
        <WalletPurchaseDrawer onClose={closeCatalog} onPurchased={onPurchased} />
      ) : null}
    </ConsoleLayout>
  )
}

function WalletBalancePanel({ refreshKey, onPurchase }: { refreshKey: number; onPurchase: () => void }) {
  const [balance, setBalance] = useState<WalletBalance | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    void apiFetch<WalletBalance>('/api/v1/auth/wallet')
      .then((value) => { if (active) { setBalance(value); setError('') } })
      .catch((reason: unknown) => {
        if (active) { setBalance(null); setError(reason instanceof Error ? reason.message : '余额加载失败。') }
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [refreshKey])

  const amount = balance ? formatPoints(balance.balance) : '—'
  const label = `当前余额 ${loading ? '加载中' : amount} 辰星点`

  return (
    <HudPanel>
      {error ? <div className="mb-4"><Notice tone="warning">{error}</Notice></div> : null}
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="min-w-0">
          <p className="chenxing-caption">当前余额</p>
          <p className="chenxing-display text-aurora mt-3 text-5xl font-bold tabular-nums" aria-label={label}>
            {loading ? '—' : amount}
            <span className="chenxing-body ml-3 text-base font-medium text-[var(--chenxing-muted-foreground)]">辰星点</span>
          </p>
          <p className="chenxing-caption mt-3">不是真实货币。购买套餐会从余额扣除对应点数。</p>
        </div>
        <Button icon="crown" onClick={onPurchase}>购买订阅</Button>
      </div>
    </HudPanel>
  )
}

function WalletLedger({ refreshKey }: { refreshKey: number }) {
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<Paged<WalletLedgerEntry> | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    setLoading(true)
    void apiFetch<Paged<WalletLedgerEntry>>(`/api/v1/auth/wallet/ledger?page=${page}&page_size=${PAGE_SIZE}`)
      .then((data) => {
        if (!active) return
        const totalPages = Math.max(1, Math.ceil(data.total / data.page_size))
        if (page > totalPages) { setPage(totalPages); return }
        setResult(data)
        setError('')
      })
      .catch((reason: unknown) => {
        if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '账单加载失败。') }
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [page, refreshKey])

  const totalPages = result ? Math.max(1, Math.ceil(result.total / result.page_size)) : 1

  return (
    <TablePanel
      className="mt-6"
      icon="receipt"
      title="账单"
      description={result ? `共 ${result.total} 条` : '充值、购买与调整记录'}
      notice={error ? <Notice tone="warning">{error}</Notice> : null}
    >
      <DataTable
        minWidth={720}
        columns={['时间', '类型', '变动', '余额', '备注']}
        empty={result?.items.length
          ? null
          : loading ? '正在加载账单。' : error ? '无法加载账单。' : '暂无账单记录。'}
      >
        {result?.items.map((entry) => (
          <tr key={entry.id}>
            <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(entry.created_at)}</td>
            <td>
              <Badge tone={KIND_TONE[entry.kind] ?? 'neutral'}>{kindLabel(entry.kind)}</Badge>
            </td>
            <td className={`chenxing-mono text-sm ${entry.amount > 0 ? 'text-[var(--chenxing-cyan)]' : ''}`}>
              {formatDelta(entry.amount)}
            </td>
            <td className="chenxing-mono text-sm">{formatPoints(entry.balance_after)}</td>
            <td className="chenxing-caption max-w-xs truncate" title={entry.note ?? undefined}>{entry.note || '—'}</td>
          </tr>
        ))}
      </DataTable>
      {result && result.total > 0 ? (
        <TablePagination page={page} totalPages={totalPages} total={result.total} onPageChange={setPage} />
      ) : null}
    </TablePanel>
  )
}
