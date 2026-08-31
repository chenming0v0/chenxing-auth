import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ApiError } from '../../api'
import { ConsoleWallet } from './wallet'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
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

const EMPTY_LEDGER = { items: [], page: 1, page_size: 20, total: 0 }

function mockWalletApis(options?: { purchaseError?: ApiError }) {
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
    if (path === '/api/v1/auth/wallet/purchase' && method === 'POST') {
      if (options?.purchaseError) return Promise.reject(options.purchaseError)
      return Promise.resolve({ balance: 0, plan_id: 7, plan_expires_at: null })
    }
    return Promise.reject(new Error(`unexpected ${method} ${path}`))
  })
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/wallet')
  apiFetchMock.mockReset()
  mockWalletApis()
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
