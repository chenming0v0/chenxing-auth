import { useEffect, useState } from 'react'
import { apiFetch, type QuotaAddon, type QuotaAddonPurchaseResult } from '../../api'
import { Badge, Button, HudPanel, Icon, Notice } from '../../components/ui'
import { useMutationLock } from '../../use-mutation-lock'

function points(value: number): string { return value.toLocaleString('zh-CN') }

export function WalletAddonPanel({ onPurchased }: { onPurchased: () => void }) {
  const [items, setItems] = useState<QuotaAddon[] | null>(null)
  const [error, setError] = useState('')
  const { busy, run } = useMutationLock()

  useEffect(() => {
    let active = true
    void apiFetch<QuotaAddon[]>('/api/v1/auth/quota-addons/catalog')
      .then((value) => { if (active) { setItems(value); setError('') } })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '增量包加载失败。') })
    return () => { active = false }
  }, [])

  async function purchase(item: QuotaAddon) {
    if (!window.confirm(`确认用 ${points(item.price_points)} 辰星点购买「${item.name}」？`)) return
    setError('')
    await run(async () => {
      try {
        await apiFetch<QuotaAddonPurchaseResult>('/api/v1/auth/quota-addons/purchase', {
          method: 'POST', body: JSON.stringify({ addon_id: item.id }),
        })
        onPurchased()
      } catch (reason) { setError(reason instanceof Error ? reason.message : '购买失败。') }
    })
  }

  return (
    <HudPanel as="section" aria-labelledby="wallet-addon-title" className="mt-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] text-[var(--chenxing-cyan)]">
            <Icon name="layers" size={18} />
          </span>
          <div className="min-w-0">
            <h2 id="wallet-addon-title" className="chenxing-h2">授权增量包</h2>
          </div>
        </div>
        <Badge>随当前套餐周期生效</Badge>
      </div>
      {error ? <div className="mt-4"><Notice tone="warning">{error}</Notice></div> : null}
      {items?.length === 0 ? <p className="chenxing-caption mt-4">当前套餐没有可购买的增量包。</p> : null}
      <div className="mt-5 grid gap-3 md:grid-cols-2">
        {items?.map((item) => (
          <div key={item.id} className="flex flex-col rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] p-4 transition-colors duration-200 hover:border-[var(--chenxing-border-strong)]">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="chenxing-body font-semibold">{item.name}</p>
                <p className="chenxing-caption mt-1">{item.description || item.code}</p>
              </div>
              <p className="chenxing-mono shrink-0 text-[var(--chenxing-cyan)]">{points(item.price_points)} 点</p>
            </div>
            <p className="chenxing-caption mt-3">每日 +{points(item.daily_auth_limit)}，每月 +{points(item.monthly_auth_limit)}</p>
            <div className="mt-4 pt-1">
              <Button icon="plus" disabled={busy} onClick={() => void purchase(item)}>{busy ? '购买中…' : '购买增量包'}</Button>
            </div>
          </div>
        ))}
      </div>
    </HudPanel>
  )
}
