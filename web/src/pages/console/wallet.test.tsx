import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ApiError } from '../../api'
import { ConsoleWallet } from './wallet'

const { apiFetchMock, getEntitlementsMock, invalidateEntitlementsMock, cacheEvents, state } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({})),
  getEntitlementsMock: vi.fn((_force?: boolean): Promise<unknown> => Promise.resolve({ plan: null, entitlements: [] })),
  invalidateEntitlementsMock: vi.fn(),
  /** 权益缓存的读/失效时序。#687 关心的正是「先失效再重新拉取」这个顺序。 */
  cacheEvents: [] as string[],
  state: { plan: null as unknown },
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
  getEntitlements: getEntitlementsMock,
  invalidateEntitlements: invalidateEntitlementsMock,
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

const CATALOG_PLAN = {
  id: 7,
  code: 'pro',
  name: '专业版',
  description: '更多额度',
  price_points: 40,
  billing_period: 'monthly',
  oauth_clients_limit: 10,
  daily_auth_limit: 10000,
  monthly_auth_limit: 200000,
  max_qps: 20,
}

/** 购买成功后服务端返回的套餐，名字与目录条目不同，便于断言统计条真的换了内容。 */
const PURCHASED_PLAN = {
  code: 'pro',
  name: '尊享版',
  description: null,
  validity: 'permanent',
}

const QUOTA_ADDON = {
  id: 3,
  plan_id: 7,
  code: 'auth-pack',
  name: '授权增量包',
  description: '提高授权额度',
  price_points: 10,
  daily_auth_limit: 1000,
  monthly_auth_limit: 20000,
  status: 'active',
  created_at: '2026-08-01T00:00:00Z',
  updated_at: '2026-08-01T00:00:00Z',
}

const EMPTY_LEDGER = { items: [], page: 1, page_size: 20, total: 0 }

/** 网络层瞬时失败：#701 之后重试会带同一个 Idempotency-Key，由服务端重放已提交结果。 */
const TRANSIENT_ERROR = new ApiError('网络连接不可用，请稍后重试。', 0)

function mockWalletApis(options?: { purchaseError?: ApiError; transientPurchaseFailures?: number }) {
  let remainingTransient = options?.transientPurchaseFailures ?? 0
  apiFetchMock.mockImplementation((path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    if (path === '/api/v1/auth/wallet' && method === 'GET') {
      return Promise.resolve({ balance: 0, currency: 'points' })
    }
    if (path.startsWith('/api/v1/auth/wallet/ledger')) {
      return Promise.resolve(EMPTY_LEDGER)
    }
    if (path === '/api/v1/auth/plans/catalog') {
      return Promise.resolve([CATALOG_PLAN])
    }
    if (path === '/api/v1/auth/quota-addons/catalog') {
      return Promise.resolve([QUOTA_ADDON])
    }
    if (path === '/api/v1/auth/wallet/purchase' && method === 'POST') {
      if (options?.purchaseError) return Promise.reject(options.purchaseError)
      if (remainingTransient > 0) {
        remainingTransient -= 1
        return Promise.reject(TRANSIENT_ERROR)
      }
      // 重放与首次提交返回同一份已提交结果，客户端看到的都是成功。
      state.plan = PURCHASED_PLAN
      return Promise.resolve({ balance: 0, plan_id: 7, plan_expires_at: null })
    }
    if (path === '/api/v1/auth/quota-addons/purchase' && method === 'POST') {
      return Promise.resolve({ balance: 0, addon_id: QUOTA_ADDON.id, plan_expires_at: null })
    }
    return Promise.reject(new Error(`unexpected ${method} ${path}`))
  })
}

function purchaseCalls() {
  return apiFetchMock.mock.calls.filter(([path, init]) =>
    path === '/api/v1/auth/wallet/purchase' && init?.method === 'POST')
}

function idempotencyKeyOf(init?: RequestInit): unknown {
  return (init?.headers as Record<string, string> | undefined)?.['Idempotency-Key']
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/wallet')
  apiFetchMock.mockReset()
  getEntitlementsMock.mockReset()
  invalidateEntitlementsMock.mockReset()
  cacheEvents.length = 0
  state.plan = null
  mockWalletApis()
  getEntitlementsMock.mockImplementation((force?: boolean) => {
    cacheEvents.push(force ? 'read:force' : 'read')
    return Promise.resolve({ plan: state.plan, entitlements: [] })
  })
  invalidateEntitlementsMock.mockImplementation(() => { cacheEvents.push('invalidate') })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ConsoleWallet', () => {
  it('renders a zero balance', async () => {
    render(<ConsoleWallet />)
    expect(await screen.findByLabelText('当前余额 0 辰星点')).toBeTruthy()
    expect(screen.getByText('辰星点')).toBeTruthy()
  })

  it('shows the purchase subscription action', async () => {
    render(<ConsoleWallet />)
    expect(await screen.findByRole('button', { name: '购买订阅' })).toBeTruthy()
  })

  it('opens the catalog when purchase=1 is in the query', async () => {
    window.history.replaceState({}, '', '/console/wallet?purchase=1')
    render(<ConsoleWallet />)
    expect(await screen.findByRole('dialog', { name: '购买订阅' })).toBeTruthy()
    expect(await screen.findByText('专业版')).toBeTruthy()
    expect(apiFetchMock.mock.calls.some(([path]) => path === '/api/v1/auth/plans/catalog')).toBe(true)
  })

  it('shows insufficient balance and does not claim a purchase', async () => {
    mockWalletApis({
      purchaseError: new ApiError('辰星点不足，无法购买该套餐。', 400, 'insufficient_balance'),
    })
    vi.stubGlobal('confirm', () => true)
    window.history.replaceState({}, '', '/console/wallet?purchase=1')
    render(<ConsoleWallet />)
    await screen.findByText('专业版')
    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    await waitFor(() => {
      expect(screen.getByRole('alert').textContent).toContain('辰星点不足，无法购买该套餐。')
    })
    expect(screen.queryByText('已购买')).toBeNull()
    expect(screen.getByRole('dialog', { name: '购买订阅' })).toBeTruthy()
    const purchaseCall = apiFetchMock.mock.calls.find(([path, init]) =>
      path === '/api/v1/auth/wallet/purchase' && init?.method === 'POST')
    expect(purchaseCall?.[1]?.headers).toEqual({ 'Idempotency-Key': expect.any(String) })
  })

  it('redeems a wallet card and refreshes the wallet', async () => {
    apiFetchMock.mockImplementation((path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (path === '/api/v1/auth/wallet' && method === 'GET') return Promise.resolve({ balance: 120, currency: 'points' })
      if (path.startsWith('/api/v1/auth/wallet/ledger')) return Promise.resolve(EMPTY_LEDGER)
      if (path === '/api/v1/auth/wallet/redeem' && method === 'POST') return Promise.resolve({ balance: 120, points: 100 })
      return Promise.reject(new Error(`unexpected ${method} ${path}`))
    })
    render(<ConsoleWallet />)
    const input = await screen.findByLabelText('兑换码')
    fireEvent.change(input, { target: { value: 'card-plain-once' } })
    fireEvent.click(screen.getByRole('button', { name: '立即兑换' }))
    await screen.findByText('兑换成功，已到账 100 辰星点。')
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/wallet/redeem', expect.objectContaining({ method: 'POST' }))
  })

  it('shows a redeem error without clearing the entered code', async () => {
    apiFetchMock.mockImplementation((path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (path === '/api/v1/auth/wallet' && method === 'GET') return Promise.resolve({ balance: 0, currency: 'points' })
      if (path.startsWith('/api/v1/auth/wallet/ledger')) return Promise.resolve(EMPTY_LEDGER)
      if (path === '/api/v1/auth/wallet/redeem' && method === 'POST') return Promise.reject(new ApiError('兑换码不存在、已使用、已停用或已过期。', 400, 'invalid_redemption_code'))
      return Promise.reject(new Error(`unexpected ${method} ${path}`))
    })
    render(<ConsoleWallet />)
    const input = await screen.findByLabelText('兑换码') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'expired-card' } })
    fireEvent.click(screen.getByRole('button', { name: '立即兑换' }))
    await screen.findByText('兑换码不存在、已使用、已停用或已过期。')
    expect(input.value).toBe('expired-card')
  })
})

/**
 * #687：购买成功后必须失效共享的权益缓存，并重新拉取。
 *
 * 只 mock 网络与缓存边界，钱包页、抽屉和增量包面板都跑真实实现，这样断言的是
 * 「成功回调链条真的走到了失效 + 重新拉取」，而不是某个 hook 的内部行为。
 */
describe('ConsoleWallet 购买后失效权益缓存（#687）', () => {
  beforeEach(() => {
    vi.stubGlobal('confirm', () => true)
  })

  it('invalidates the entitlement cache before refetching after a plan purchase', async () => {
    window.history.replaceState({}, '', '/console/wallet?purchase=1')
    render(<ConsoleWallet />)
    await screen.findByText('专业版')
    // 首屏已经读过一次权益，缓存里是购买前的状态（此处为未订阅）
    await waitFor(() => expect(cacheEvents).toEqual(['read:force']))

    fireEvent.click(screen.getByRole('button', { name: '购买' }))

    // 失效必须发生在下一次读取之前，否则重新拉取仍可能命中购买前的缓存
    await waitFor(() => expect(cacheEvents).toEqual(['read:force', 'invalidate', 'read:force']))
    expect(invalidateEntitlementsMock).toHaveBeenCalledTimes(1)
    // 重新拉取的结果真的渲染出来：统计条与订阅卡都换成购买后的套餐
    expect(await screen.findByText('已购买')).toBeTruthy()
    await waitFor(() => expect(screen.getAllByText('尊享版').length).toBeGreaterThan(0))
    expect(screen.queryByRole('dialog', { name: '购买订阅' })).toBeNull()
  })

  it('invalidates the entitlement cache before refetching after a quota add-on purchase', async () => {
    render(<ConsoleWallet />)
    const button = await screen.findByRole('button', { name: '购买增量包' })
    await waitFor(() => expect(cacheEvents).toEqual(['read:force']))

    fireEvent.click(button)

    await waitFor(() => expect(cacheEvents).toEqual(['read:force', 'invalidate', 'read:force']))
    expect(invalidateEntitlementsMock).toHaveBeenCalledTimes(1)
    expect(await screen.findByText('增量包已购买')).toBeTruthy()
  })

  it('invalidates the cache when a retry replays the same Idempotency-Key', async () => {
    // #701：购买强制要求 Idempotency-Key，重试同一个键会返回已提交结果。
    // 对客户端而言这依然是「购买成功」，失效逻辑必须照样生效。
    mockWalletApis({ transientPurchaseFailures: 1 })
    window.history.replaceState({}, '', '/console/wallet?purchase=1')
    render(<ConsoleWallet />)
    await screen.findByText('专业版')

    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    await screen.findByText('网络连接不可用，请稍后重试。')
    // 首次尝试没有确认成功，此时不该失效任何缓存
    expect(invalidateEntitlementsMock).not.toHaveBeenCalled()

    fireEvent.click(screen.getByRole('button', { name: '购买' }))
    await waitFor(() => expect(cacheEvents).toEqual(['read:force', 'invalidate', 'read:force']))

    const calls = purchaseCalls()
    expect(calls).toHaveLength(2)
    // 重放的判据：两次提交带的是同一个幂等键
    expect(idempotencyKeyOf(calls[0][1])).toEqual(expect.any(String))
    expect(idempotencyKeyOf(calls[1][1])).toBe(idempotencyKeyOf(calls[0][1]))
    expect(invalidateEntitlementsMock).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getAllByText('尊享版').length).toBeGreaterThan(0))
  })
})
