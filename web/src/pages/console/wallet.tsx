import { useEffect, useState } from 'react'
import { apiFetch, type EntitlementPlan, type EntitlementsResponse, type Paged, type WalletBalance, type WalletLedgerEntry } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, HudPanel, Icon, Notice, PageIntro } from '@chenxing/ui'
import { DataTable, TablePagination, TablePanel } from '@chenxing/ui'
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

/** 套餐信息三态：加载失败不阻塞钱包主流程，统计条与订阅卡各自降级展示。 */
type PlanState =
  | { kind: 'loading' }
  | { kind: 'ready'; plan: EntitlementPlan | null }
  | { kind: 'error' }

function planValidityText(plan: EntitlementPlan): string {
  return plan.validity === 'permanent' ? '永久有效' : `有效至 ${formatDate(plan.validity)}`
}

export function ConsoleWallet() {
  const location = useLocation()
  const purchaseRequested = new URLSearchParams(location.search).get('purchase') === '1'
  const [catalogOpen, setCatalogOpen] = useState(purchaseRequested)
  const [notice, setNotice] = useState('')
  const [refreshKey, setRefreshKey] = useState(0)
  const [planState, setPlanState] = useState<PlanState>({ kind: 'loading' })
  const [ledgerTotal, setLedgerTotal] = useState<number | null>(null)

  useEffect(() => {
    if (purchaseRequested) setCatalogOpen(true)
  }, [purchaseRequested])

  // 直接请求而不是走 getEntitlements 缓存：购买/兑换后 refreshKey 变化必须拿到最新套餐。
  useEffect(() => {
    let active = true
    setPlanState({ kind: 'loading' })
    void apiFetch<EntitlementsResponse>('/api/v1/auth/entitlements')
      .then((value) => { if (active) setPlanState({ kind: 'ready', plan: value.plan }) })
      .catch(() => { if (active) setPlanState({ kind: 'error' }) })
    return () => { active = false }
  }, [refreshKey])

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
      <WalletStatsStrip refreshKey={refreshKey} planState={planState} ledgerTotal={ledgerTotal} />
      <div className="mt-6 grid items-stretch gap-6 lg:grid-cols-2">
        <WalletRedeemPanel onRedeemed={() => { setNotice('兑换卡已到账'); setRefreshKey((value) => value + 1) }} />
        <WalletSubscriptionPanel planState={planState} onPurchase={() => { setNotice(''); setCatalogOpen(true) }} />
      </div>
      <WalletAddonPanel onPurchased={() => { setNotice('增量包已购买'); setRefreshKey((value) => value + 1) }} />
      <WalletLedger refreshKey={refreshKey} onTotal={setLedgerTotal} />
      {catalogOpen ? (
        <WalletPurchaseDrawer onClose={closeCatalog} onPurchased={onPurchased} />
      ) : null}
    </ConsoleLayout>
  )
}

/** 统计条单元格：小图标 + 标签在上，数值主体在中，可选说明在下。 */
function StatCell({ icon, tone = 'cyan', label, sub, children }: {
  icon: string
  tone?: 'cyan' | 'gold'
  label: string
  sub?: string
  children: React.ReactNode
}) {
  const toneClass = tone === 'gold' ? 'text-[var(--chenxing-gold)]' : 'text-[var(--chenxing-cyan)]'
  return (
    <div className="min-w-0 py-5 first:pt-0 last:pb-0 sm:py-0 sm:px-7 sm:first:pl-0 sm:last:pr-0">
      <div className="flex items-center gap-2.5">
        <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] ${toneClass}`}>
          <Icon name={icon} size={15} />
        </span>
        <p className="chenxing-caption">{label}</p>
      </div>
      {/* min-h 让三格数值底线对齐：余额/条数是大号数字，套餐名字号更小 */}
      <div className="mt-4 flex min-h-[2.75rem] items-end">{children}</div>
      {sub ? <p className="chenxing-caption mt-2">{sub}</p> : null}
    </div>
  )
}

function WalletStatsStrip({ refreshKey, planState, ledgerTotal }: {
  refreshKey: number
  planState: PlanState
  ledgerTotal: number | null
}) {
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

  const plan = planState.kind === 'ready' ? planState.plan : null
  const planName = planState.kind === 'loading' ? '—' : planState.kind === 'error' ? '—' : plan ? plan.name : '未订阅'
  const planSub = planState.kind === 'loading'
    ? '正在加载套餐信息'
    : planState.kind === 'error'
      ? '套餐信息暂不可用'
      : plan ? planValidityText(plan) : '购买订阅后在此显示'

  return (
    <HudPanel>
      {error ? <div className="mb-5"><Notice tone="warning">{error}</Notice></div> : null}
      <div className="grid divide-y divide-[var(--chenxing-border)] sm:grid-cols-3 sm:divide-y-0 sm:divide-x">
        <StatCell icon="wallet" label="当前余额">
          <p className="chenxing-display text-aurora text-4xl font-bold tabular-nums" aria-label={label}>
            {loading ? '—' : amount}
            <span className="chenxing-body ml-2 text-sm font-medium text-[var(--chenxing-muted-foreground)]">辰星点</span>
          </p>
        </StatCell>
        <StatCell icon="crown" tone="gold" label="当前套餐" sub={planSub}>
          <p className="chenxing-display truncate text-2xl font-semibold" title={planName}>{planName}</p>
        </StatCell>
        <StatCell icon="receipt" label="账单记录">
          <p className="chenxing-display text-4xl font-bold tabular-nums">
            {ledgerTotal === null ? '—' : formatPoints(ledgerTotal)}
            <span className="chenxing-body ml-2 text-sm font-medium text-[var(--chenxing-muted-foreground)]">条</span>
          </p>
        </StatCell>
      </div>
    </HudPanel>
  )
}

function WalletSubscriptionPanel({ planState, onPurchase }: {
  planState: PlanState
  onPurchase: () => void
}) {
  const plan = planState.kind === 'ready' ? planState.plan : null
  return (
    <HudPanel as="section" aria-labelledby="wallet-subscription-title" className="flex flex-col">
      <div className="flex items-start gap-3.5">
        <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-gold)]">
          <Icon name="crown" size={18} />
        </span>
        <div className="min-w-0">
          <h2 id="wallet-subscription-title" className="chenxing-h2">订阅套餐</h2>
          <p className="chenxing-caption mt-1">订阅套餐以获取接入额度与权益。</p>
        </div>
      </div>
      <div className="mt-5 flex-1 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] p-4">
        <p className="chenxing-caption">我的订阅</p>
        {plan ? (
          <div className="mt-2 flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="chenxing-body font-semibold">{plan.name}</p>
              <p className="chenxing-caption mt-1 truncate" title={plan.description || plan.code}>{plan.description || plan.code}</p>
            </div>
            <Badge tone="success">{planValidityText(plan)}</Badge>
          </div>
        ) : (
          <p className="chenxing-caption mt-2">
            {planState.kind === 'loading' ? '正在加载套餐信息。' : planState.kind === 'error' ? '套餐信息暂不可用。' : '尚未订阅套餐。'}
          </p>
        )}
      </div>
      <div className="mt-5 flex justify-end">
        <Button icon="crown" onClick={onPurchase}>购买订阅</Button>
      </div>
    </HudPanel>
  )
}

function WalletLedger({ refreshKey, onTotal }: { refreshKey: number; onTotal: (total: number) => void }) {
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
        onTotal(data.total)
      })
      .catch((reason: unknown) => {
        if (active) { setResult(null); setError(reason instanceof Error ? reason.message : '账单加载失败。') }
      })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
    // onTotal 是父组件的 setState，引用稳定，不列入依赖以避免无谓重跑。
    // eslint-disable-next-line react-hooks/exhaustive-deps
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
