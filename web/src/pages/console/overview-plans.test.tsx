import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ConsoleOverview } from './overview-plans'

/**
 * #273：摘要与权益是两个独立请求，共用同一个 Notice。这里按「哪一个失败」驱动
 * 首次加载与重试，断言重试真的重新请求了失败的那一侧。
 *
 * 只 mock 网络边界（api 模块），useAccountSummary / useEntitlements 与 Notice
 * 都跑真实实现，否则测不到「重试按钮到底调了谁」。
 */

const SUMMARY_PATHS = [
  '/api/v1/auth/oauth-clients',
  '/api/v1/auth/sessions',
  '/api/v1/auth/authorized-apps',
] as const

const summaryBodies: Record<string, unknown> = {
  '/api/v1/auth/oauth-clients': {
    items: [{
      id: 1, client_id: 'cid-1', client_name: '深空控制台', redirect_uris: ['https://example.test/cb'],
      scopes: ['openid'], status: 'active',
      quota: { daily_limit: 100, daily_used: 1, monthly_limit: 2000, monthly_used: 12 },
      auth_method: 'client_secret_basic', logo_uri: null, client_uri: null,
    }],
  },
  '/api/v1/auth/sessions': {
    items: [
      { id: 1, created_at: '2026-08-01T00:00:00Z', expires_at: '2026-08-20T00:00:00Z', current: true },
      { id: 2, created_at: '2026-08-02T00:00:00Z', expires_at: '2026-08-21T00:00:00Z', current: false },
    ],
  },
  '/api/v1/auth/authorized-apps': {
    items: [{ client_id: 'cid-9', client_name: '深空日志', scopes: ['openid', 'profile'], updated_at: '2026-08-05T00:00:00Z' }],
  },
}

const entitlementsBody = {
  plan: { code: 'BASIC', name: '基础版', description: null, validity: 'permanent' },
  entitlements: [{ key: 'oauth_clients', label: 'OAuth 应用', used: 1, limit: 2, remaining: 1 }],
}

const SUMMARY_ERROR = '账户摘要接口暂时不可用。'
const ENTITLEMENT_ERROR = '权益接口暂时不可用。'

const { apiFetchMock, getEntitlementsMock, state } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({ items: [] })),
  getEntitlementsMock: vi.fn((_force?: boolean): Promise<unknown> => new Promise(() => {})),
  state: { summaryFails: false, entitlementsFails: false, calls: [] as string[] },
}))

vi.mock('../../api', () => ({
  apiFetch: apiFetchMock,
  getEntitlements: getEntitlementsMock,
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('../../auth-state', () => ({
  useAuth: () => ({
    user: {
      id: 1, username: 'chenxing', email: 'chenxing@example.test', display_name: '测试员',
      status: 'active', role: 'user', current_session_expires_at: '2026-08-20T00:00:00Z',
      avatar_updated_at: null,
    },
    status: 'authenticated',
  }),
}))

beforeEach(() => {
  state.summaryFails = false
  state.entitlementsFails = false
  state.calls = []
  apiFetchMock.mockReset()
  getEntitlementsMock.mockReset()
  apiFetchMock.mockImplementation((path: string) => {
    state.calls.push(path)
    if (state.summaryFails) return Promise.reject(new Error(SUMMARY_ERROR))
    return Promise.resolve(summaryBodies[path] ?? { items: [] })
  })
  getEntitlementsMock.mockImplementation(() => {
    state.calls.push('entitlements')
    if (state.entitlementsFails) return Promise.reject(new Error(ENTITLEMENT_ERROR))
    return Promise.resolve(entitlementsBody)
  })
})

afterEach(cleanup)

/** 当前 Notice 里的重试按钮。警告 Notice 是 role=alert，页面上只有这一个。 */
function retryButton() {
  return within(screen.getByRole('alert')).getByRole('button', { name: '重试' })
}

function summaryCallCount() {
  return state.calls.filter((path) => (SUMMARY_PATHS as readonly string[]).includes(path)).length
}

function entitlementCallCount() {
  return state.calls.filter((path) => path === 'entitlements').length
}

describe('ConsoleOverview 重试按钮按错误来源重试（#273）', () => {
  it('摘要失败后点击重试重新请求三个摘要接口，成功后错误消失且数据渲染', async () => {
    state.summaryFails = true
    render(<ConsoleOverview />)

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain(SUMMARY_ERROR)
    expect(summaryCallCount()).toBe(3)

    state.summaryFails = false
    fireEvent.click(retryButton())

    // 等真实数据落地，而不是等错误清空：setError('') 在重试发起时就同步发生
    await screen.findByText('深空日志')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(summaryCallCount()).toBe(6)
    // 权益侧本来就成功，不该被重试连带重跑
    expect(entitlementCallCount()).toBe(1)
  })

  it('只有权益失败时，重试只重跑权益接口', async () => {
    state.entitlementsFails = true
    render(<ConsoleOverview />)

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain(ENTITLEMENT_ERROR)
    expect(entitlementCallCount()).toBe(1)
    expect(summaryCallCount()).toBe(3)

    state.entitlementsFails = false
    fireEvent.click(retryButton())

    await screen.findByText('BASIC')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(entitlementCallCount()).toBe(2)
    // 摘要侧已经成功，不重复请求
    expect(summaryCallCount()).toBe(3)
    expect(getEntitlementsMock).toHaveBeenLastCalledWith(true)
  })

  it('两者同时失败时，一次重试先补摘要再补权益，全部恢复后 Notice 消失', async () => {
    state.summaryFails = true
    state.entitlementsFails = true
    render(<ConsoleOverview />)

    const alert = await screen.findByRole('alert')
    // Notice 展示的是摘要错误，因此重试顺序也从摘要开始
    expect(alert.textContent).toContain(SUMMARY_ERROR)

    state.summaryFails = false
    state.entitlementsFails = false
    state.calls = []
    fireEvent.click(retryButton())

    await screen.findByText('深空日志')
    await screen.findByText('BASIC')
    expect(screen.queryByRole('alert')).toBeNull()
    expect(summaryCallCount()).toBe(3)
    expect(entitlementCallCount()).toBe(1)
    // 摘要三个请求先于权益请求发出
    expect(state.calls.indexOf('entitlements')).toBe(3)
  })

  it('摘要恢复但权益仍失败时，Notice 切换到权益错误并仍可继续重试', async () => {
    state.summaryFails = true
    state.entitlementsFails = true
    render(<ConsoleOverview />)
    await screen.findByRole('alert')

    state.summaryFails = false
    state.calls = []
    fireEvent.click(retryButton())

    await screen.findByText('深空日志')
    await waitFor(() => { expect(screen.getByRole('alert').textContent).toContain(ENTITLEMENT_ERROR) })
    expect(summaryCallCount()).toBe(3)
    expect(entitlementCallCount()).toBe(1)

    state.entitlementsFails = false
    state.calls = []
    fireEvent.click(retryButton())

    await screen.findByText('BASIC')
    expect(screen.queryByRole('alert')).toBeNull()
    // 摘要已恢复，第二次重试只补权益
    expect(summaryCallCount()).toBe(0)
    expect(entitlementCallCount()).toBe(1)
  })
})
