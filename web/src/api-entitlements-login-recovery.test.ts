import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch, clearApiCache, getEntitlements, invalidateEntitlements, loginRecoveryTarget } from './api'

/** 构造 apiFetch 只需要的 Response 子集，避免依赖 jsdom 的 Response 实现细节。 */
function stubResponse(init: { status: number; body?: unknown; jsonThrows?: boolean; jsonError?: unknown }): Response {
  return {
    ok: init.status >= 200 && init.status < 300,
    status: init.status,
    json: () => (init.jsonThrows
      ? Promise.reject(init.jsonError ?? new Error('not json'))
      : Promise.resolve(init.body)),
  } as unknown as Response
}

/** 用推断而非 vi.fn 的显式泛型，避免绑定到特定 vitest 版本的 Mock 类型签名。 */
function createFetchMock() {
  return vi.fn((_input: string, _init?: RequestInit): Promise<Response> =>
    Promise.resolve(stubResponse({ status: 200, body: {} })))
}

type FetchMock = ReturnType<typeof createFetchMock>

function headersOf(mock: FetchMock, call = 0): Headers {
  return new Headers(mock.mock.calls[call][1]?.headers)
}
/**
 * #687：套餐/增量包购买成功后必须失效权益缓存，且只失效权益这一项。
 * 这里断言两件事：失效确实让下一次读取重新请求服务端；失效不额外发请求、
 * 不影响其他端点的请求序列，也就是精确失效而非全量清空。
 */
describe('invalidateEntitlements', () => {
  let fetchMock: FetchMock

  const FIRST = { plan: { code: 'free', name: '免费版', description: null, validity: 'permanent' }, entitlements: [] }
  const SECOND = { plan: { code: 'pro', name: '专业版', description: null, validity: '2099-01-01T00:00:00Z' }, entitlements: [] }

  function entitlementCalls(): string[] {
    return fetchMock.mock.calls
      .map(([path]) => path)
      .filter((path) => path === '/api/v1/auth/entitlements')
  }

  beforeEach(() => {
    fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)
    clearApiCache()
  })

  afterEach(() => {
    clearApiCache()
    vi.unstubAllGlobals()
  })

  it('makes the next read hit the server again', async () => {
    fetchMock.mockResolvedValueOnce(stubResponse({ status: 200, body: FIRST }))
    expect(await getEntitlements()).toEqual(FIRST)
    // 未失效时第二次读取命中缓存，不产生请求
    expect(await getEntitlements()).toEqual(FIRST)
    expect(entitlementCalls()).toHaveLength(1)

    invalidateEntitlements()
    fetchMock.mockResolvedValueOnce(stubResponse({ status: 200, body: SECOND }))
    expect(await getEntitlements()).toEqual(SECOND)
    expect(entitlementCalls()).toHaveLength(2)
  })

  it('clears only the entitlement cache and issues no request itself', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: FIRST }))
    await getEntitlements()
    await apiFetch('/api/v1/auth/wallet')
    const before = fetchMock.mock.calls.length

    invalidateEntitlements()
    // 失效本身不发请求：它只丢弃权益缓存与在途引用
    expect(fetchMock.mock.calls.length).toBe(before)

    // 其他端点不经缓存，失效前后请求行为完全一致
    await apiFetch('/api/v1/auth/wallet')
    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/v1/auth/wallet')).toHaveLength(2)
    expect(entitlementCalls()).toHaveLength(1)
  })

  it('keeps a response issued before invalidation out of the cache', async () => {
    // 购买成功后立刻失效，但购买前发出的读取可能还在途：它 resolve 后
    // 不得把购买前的权益写回缓存，否则界面继续显示旧额度。
    let resolveStale: ((response: Response) => void) | undefined
    fetchMock.mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveStale = resolve }))
    const stale = getEntitlements()

    invalidateEntitlements()
    resolveStale?.(stubResponse({ status: 200, body: FIRST }))
    // 当次调用者照常拿到自己的响应，但它不进缓存
    expect(await stale).toEqual(FIRST)

    fetchMock.mockResolvedValueOnce(stubResponse({ status: 200, body: SECOND }))
    expect(await getEntitlements()).toEqual(SECOND)
    expect(entitlementCalls()).toHaveLength(2)
  })
})

/**
 * #270：登录恢复地址与「先绑后读」。
 *
 * 两者共同拆掉 401 登录循环：request_id 必须提升为登录页的顶层查询参数，
 * 且确认页读取待授权请求之前先做一次幂等绑定，让新会话接管旧绑定。
 */
describe('loginRecoveryTarget', () => {
  it('把 OAuth request_id 提升为顶层查询参数，同时保留 returnTo', () => {
    const target = loginRecoveryTarget('/oauth/consent', '?request_id=req-270')
    const params = new URLSearchParams(target.slice(target.indexOf('?')))
    expect(target.startsWith('/login?')).toBe(true)
    expect(params.get('request_id')).toBe('req-270')
    expect(params.get('returnTo')).toBe('/oauth/consent?request_id=req-270')
  })

  it('非 OAuth 场景只带 returnTo，行为与改动前一致', () => {
    expect(loginRecoveryTarget('/console/profile', '')).toBe('/login?returnTo=%2Fconsole%2Fprofile')
    expect(loginRecoveryTarget('/console', '?tab=security'))
      .toBe('/login?returnTo=%2Fconsole%3Ftab%3Dsecurity')
  })

  it('对 request_id 中的保留字符只编码一次', () => {
    const requestId = 'req/with?reserved=1'
    const target = loginRecoveryTarget('/oauth/consent', `?request_id=${encodeURIComponent(requestId)}`)
    expect(new URLSearchParams(target.slice(target.indexOf('?'))).get('request_id')).toBe(requestId)
  })
})
