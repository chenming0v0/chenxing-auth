export type BillingPeriod = 'one_time' | 'monthly' | 'yearly'

export type AdminPlan = {
  id: number
  code: string
  name: string
  description: string | null
  oauth_clients_limit: number
  daily_auth_limit: number
  /** null 表示无限额度 */
  monthly_auth_limit: number | null
  /** null 表示不限并发 */
  max_qps: number | null
  /** 0 表示仅管理员分配，用户不能自助购买。 */
  price_points: number
  billing_period: BillingPeriod | string
  is_default: boolean
  status: 'active' | 'archived' | string
  assigned_users: number
}
export type AdminPlanInput = {
  code: string
  name: string
  description: string | null
  oauth_clients_limit: number
  daily_auth_limit: number
  monthly_auth_limit: number | null
  max_qps: number | null
  price_points: number
  billing_period: BillingPeriod
  is_default: boolean
}

export type WalletBalance = { balance: number; currency: 'points' | string }
export type WalletLedgerKind = 'credit' | 'purchase' | 'adjust'
export type WalletLedgerEntry = {
  id: number
  amount: number
  balance_after: number
  kind: WalletLedgerKind | string
  note: string | null
  reference_type: string | null
  reference_id: string | null
  created_at: string
}
export type CatalogPlan = {
  id: number
  code: string
  name: string
  description: string | null
  price_points: number
  billing_period: BillingPeriod | string
  oauth_clients_limit: number
  daily_auth_limit: number
  monthly_auth_limit: number | null
  max_qps: number | null
}
export type WalletPurchaseResult = {
  balance: number
  plan_id: number
  plan_expires_at: string | null
}
export type QuotaAddon = {
  id: number
  plan_id: number
  code: string
  name: string
  description: string | null
  price_points: number
  daily_auth_limit: number
  monthly_auth_limit: number
  status: string
  created_at: string
  updated_at: string
}
export type QuotaAddonPurchaseResult = {
  balance: number
  addon_id: number
  plan_expires_at: string | null
}
export type WalletCreditResult = { user_id: number; balance: number }
export type WalletRedeemResult = { balance: number; points: number }
export type WalletRedemptionCardSummary = {
  id: number
  points: number
  use_count: number
  max_uses: number
  label: string | null
  expires_at: string | null
  disabled_at: string | null
  created_at: string
}
export type CreatedWalletRedemptionCard = WalletRedemptionCardSummary & { code: string }
export type WalletRedemptionCardDetail = WalletRedemptionCardSummary & {
  uses: Array<{ user_id: number; username: string; display_name: string | null; points: number; redeemed_at: string }>
}
export type AssignPlanInput = { plan_id: number; expires_at: string | null }
