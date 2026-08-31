import { useEffect, useRef, useState } from 'react'
import { apiFetch, type CatalogPlan, type WalletPurchaseResult } from '../../api'
import { Drawer } from '@chenxing/ui'
import { Badge, Button, Chip, HudPanel, Notice } from '@chenxing/ui'
import { newIdempotencyKey } from './developer-shared'
import { useMutationLock } from '../../use-mutation-lock'

const BILLING_LABEL: Record<string, string> = {
  one_time: '一次性',
  monthly: '每月',
  yearly: '每年',
}

function billingLabel(period: string): string {
  return BILLING_LABEL[period] ?? period
}

function formatPoints(value: number): string {
  return value.toLocaleString('zh-CN')
}

export function WalletPurchaseDrawer({ onClose, onPurchased }: {
  onClose: () => void
  onPurchased: () => void
}) {
  const [plans, setPlans] = useState<CatalogPlan[] | null>(null)
  const [error, setError] = useState('')
  const purchaseIdempotencyRef = useRef<{ planId: number; key: string } | null>(null)
  const { busy, run } = useMutationLock()

  useEffect(() => {
    let active = true
    void apiFetch<CatalogPlan[]>('/api/v1/auth/plans/catalog')
      .then((value) => { if (active) { setPlans(value); setError('') } })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : '套餐目录加载失败。')
      })
    return () => { active = false }
  }, [])

  async function buy(plan: CatalogPlan) {
    if (plan.price_points <= 0) return
    if (!window.confirm(`确认用 ${formatPoints(plan.price_points)} 辰星点购买「${plan.name}」？`)) return
    setError('')
    await run(async () => {
      const pending = purchaseIdempotencyRef.current
      const key = pending?.planId === plan.id ? pending.key : newIdempotencyKey()
      purchaseIdempotencyRef.current = { planId: plan.id, key }
      try {
        await apiFetch<WalletPurchaseResult>('/api/v1/auth/wallet/purchase', {
          method: 'POST',
          headers: { 'Idempotency-Key': key },
          body: JSON.stringify({ plan_id: plan.id }),
        })
        purchaseIdempotencyRef.current = null
        onPurchased()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : '购买失败。')
      }
    })
  }

  const loading = plans === null && !error

  return (
    <Drawer
      title="购买订阅"
      description="用辰星点购买套餐。售价为 0 的套餐只能由管理员分配。"
      onClose={onClose}
      onSubmit={(event) => event.preventDefault()}
      busy={busy}
      footer={<Button type="button" variant="ghost" onClick={onClose} disabled={busy}>关闭</Button>}
    >
      {error ? <Notice tone="warning">{error}</Notice> : null}
      <HudPanel className="space-y-3 !p-5">
        {loading ? <Notice>正在加载套餐目录。</Notice> : null}
        {plans?.length === 0 ? <Notice>当前没有可展示的套餐。</Notice> : null}
        {plans?.map((plan) => {
          const purchasable = plan.price_points > 0
          return (
            <div
              key={plan.id}
              className="flex flex-wrap items-start justify-between gap-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] p-4"
            >
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="chenxing-body text-sm font-semibold">{plan.name}</p>
                  <Badge>{plan.code}</Badge>
                </div>
                {plan.description ? <p className="chenxing-caption mt-1">{plan.description}</p> : null}
                <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-cyan)]">
                  {purchasable ? `${formatPoints(plan.price_points)} 辰星点 · ${billingLabel(plan.billing_period)}` : '不可自助购买'}
                </p>
              </div>
              {purchasable ? (
                <Button type="button" icon="crown" disabled={busy} onClick={() => void buy(plan)}>
                  {busy ? '购买中…' : '购买'}
                </Button>
              ) : <Chip>仅管理员分配</Chip>}
            </div>
          )
        })}
      </HudPanel>
    </Drawer>
  )
}
