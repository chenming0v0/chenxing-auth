import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { EntitlementsResponse, OwnedOAuthClient } from '../../api'
import { entitlementState, listAllOwnedOAuthClients, OWNED_CLIENT_LIST_COMPAT_ERROR } from './shared'
import { formatQuota, httpsUriProblem } from './developer-shared'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({ items: [] })),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

const withPlan: EntitlementsResponse = {
  plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' },
  entitlements: [{ key: 'oauth_clients', label: 'OAuth 应用', used: 1, limit: 2, remaining: 1 }],
}
const withoutPlan: EntitlementsResponse = { plan: null, entitlements: [] }

describe('entitlementState', () => {
  it('reports closed when plan is null (self-service not open)', () => {
    const state = entitlementState({ data: withoutPlan, error: '', loading: false })
    expect(state.kind).toBe('closed')
  })

  it('reports ready with a non-null plan narrowed for callers', () => {
    const state = entitlementState({ data: withPlan, error: '', loading: false })
    expect(state.kind).toBe('ready')
    if (state.kind !== 'ready') throw new Error('expected ready')
    expect(state.plan.code).toBe('basic')
  })

  it('reports loading before the first response arrives', () => {
    expect(entitlementState({ data: null, error: '', loading: true }).kind).toBe('loading')
  })

  it('reports failed with the request error when no data was ever loaded', () => {
    const state = entitlementState({ data: null, error: '网络连接不可用，请稍后重试。', loading: false })
    expect(state).toEqual({ kind: 'failed', message: '网络连接不可用，请稍后重试。' })
  })

  it('keeps the closed state even if a later retry fails', () => {
    // 已有数据优先：重试失败不应把「未开放自助接入」退回成错误页
    const state = entitlementState({ data: withoutPlan, error: '服务暂时不可用，请稍后重试。', loading: false })
    expect(state.kind).toBe('closed')
  })

  it('falls back to a generic message when the failure carries no text', () => {
    const state = entitlementState({ data: null, error: '', loading: false })
    expect(state).toEqual({ kind: 'failed', message: '权益数据加载失败。' })
  })
})

function fakeClient(id: number): OwnedOAuthClient {
  return {
    id,
    client_id: `cx-${id}`,
    client_name: `应用 ${id}`,
    redirect_uris: ['https://example.com/cb'],
    scopes: ['openid'],
    status: 'active',
    quota: { daily_limit: null, daily_used: 0, monthly_limit: null, monthly_used: 0 },
    auth_method: 'client_secret_basic',
    logo_uri: null,
    client_uri: null,
  }
}

function fakeClients(count: number, startId = 1): OwnedOAuthClient[] {
  return Array.from({ length: count }, (_, index) => fakeClient(startId + index))
}

describe('listAllOwnedOAuthClients', () => {
  beforeEach(() => {
    apiFetchMock.mockReset()
  })

  it('follows total across full pages and stops when offset covers the count', async () => {
    const first = fakeClients(200, 1)
    const second = fakeClients(50, 201)
    apiFetchMock
      .mockResolvedValueOnce({ items: first, total: 250 })
      .mockResolvedValueOnce({ items: second, total: 250 })

    const clients = await listAllOwnedOAuthClients()

    expect(clients.map((item) => item.id)).toEqual([...first, ...second].map((item) => item.id))
    expect(apiFetchMock.mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/auth/oauth-clients',
      '/api/v1/auth/oauth-clients?limit=200&offset=200',
    ])
  })

  it('does not request another page when total is covered by the first full page', async () => {
    const items = fakeClients(200)
    apiFetchMock.mockResolvedValueOnce({ items, total: 200 })

    const clients = await listAllOwnedOAuthClients()

    expect(clients).toHaveLength(200)
    expect(apiFetchMock).toHaveBeenCalledTimes(1)
  })

  it('treats a short page without total as the complete legacy list', async () => {
    const items = fakeClients(50)
    apiFetchMock.mockResolvedValueOnce({ items })

    const clients = await listAllOwnedOAuthClients()

    expect(clients).toEqual(items)
    expect(apiFetchMock).toHaveBeenCalledTimes(1)
    expect(apiFetchMock).toHaveBeenCalledWith('/api/v1/auth/oauth-clients')
  })

  it('stops a no-total full page followed by a short last page', async () => {
    const first = fakeClients(200, 1)
    const last = fakeClients(10, 201)
    apiFetchMock
      .mockResolvedValueOnce({ items: first })
      .mockResolvedValueOnce({ items: last })

    const clients = await listAllOwnedOAuthClients()

    expect(clients).toHaveLength(210)
    expect(apiFetchMock.mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/auth/oauth-clients',
      '/api/v1/auth/oauth-clients?limit=200&offset=200',
    ])
  })

  it('fails when a legacy full page repeats instead of looping forever', async () => {
    const page = fakeClients(200)
    apiFetchMock.mockResolvedValue({ items: page })

    await expect(listAllOwnedOAuthClients()).rejects.toThrow(OWNED_CLIENT_LIST_COMPAT_ERROR)
    expect(apiFetchMock).toHaveBeenCalledTimes(2)
    expect(apiFetchMock.mock.calls.map(([path]) => path)).toEqual([
      '/api/v1/auth/oauth-clients',
      '/api/v1/auth/oauth-clients?limit=200&offset=200',
    ])
  })
})

describe('formatQuota', () => {
  it('renders numeric limits as-is', () => {
    expect(formatQuota({ quota: { daily_used: 3, daily_limit: 100, monthly_used: 12, monthly_limit: 2000 } }))
      .toBe('今日 3/100 · 本月 12/2000')
  })

  it('renders no-plan limits as unavailable', () => {
    expect(formatQuota({ quota: { daily_used: 0, daily_limit: null, monthly_used: 0, monthly_limit: null } }))
      .toBe('今日 不可用 · 本月 不可用')
  })

  it('renders an unlimited monthly limit only for an effective plan', () => {
    expect(formatQuota({ quota: { daily_used: 3, daily_limit: 100, monthly_used: 12, monthly_limit: null } }))
      .toBe('今日 3/100 · 本月 12/∞')
  })
})

describe('httpsUriProblem', () => {
  it('accepts a public HTTPS URL', () => {
    expect(httpsUriProblem('https://cdn.example.com/logo.png')).toBeNull()
  })

  it.each([
    ['http://cdn.example.com/logo.png', '仅允许 HTTPS'],
    ['https://cdn.example.com/logo.png#x', '不允许包含 fragment'],
    ['not a url', '不是合法的 URL'],
    ['https://user:pass@cdn.example.com/logo.png', '不允许包含用户名或密码'],
  ])('rejects %s', (value, reason) => {
    expect(httpsUriProblem(value)).toBe(reason)
  })
})
