/**
 * api.ts 的安全相关行为测试：CSRF token 解析、错误文案映射（含 #97 的原型链污染回归）、
 * 以及 apiFetch 的 CSRF 头注入、204 空响应和 401 重定向路径。
 * 这里只测纯函数和可用 fetch 存根覆盖的分支，不触碰真实网络。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  ApiError, apiFetch, clearApiCache, externalLoginErrorMessage, getEntitlements,
  invalidateEntitlements, loginRecoveryTarget, parseCsrfToken, safeErrorMessage,
} from './api'
import { HISTORY_INDEX, NAVIGATION_EVENT, replaceUrl } from './router'

const SAFE_FALLBACK = '请求未完成，请稍后重试。'
/** Object.prototype 上真实存在的成员；对象字面量查表时它们会返回 Function/Object。 */
const POLLUTION_KEYS = [
  'constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty',
  'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString',
]

describe('parseCsrfToken', () => {
  it('reads the secure host-only cookie name', () => {
    expect(parseCsrfToken('__Host-chenxing_csrf=abc123')).toBe('abc123')
  })

  it('reads the token from a single cookie', () => {
    expect(parseCsrfToken('chenxing_csrf=abc123')).toBe('abc123')
  })

  it('reads the token from a cookie list regardless of position', () => {
    expect(parseCsrfToken('a=1; chenxing_csrf=abc123; b=2')).toBe('abc123')
    expect(parseCsrfToken('chenxing_csrf=abc123; b=2')).toBe('abc123')
    expect(parseCsrfToken('a=1; chenxing_csrf=abc123')).toBe('abc123')
    expect(parseCsrfToken('a=1; __Host-chenxing_csrf=abc123; b=2')).toBe('abc123')
  })

  it('tolerates missing spaces and extra whitespace between cookies', () => {
    expect(parseCsrfToken('a=1;chenxing_csrf=abc123;b=2')).toBe('abc123')
    expect(parseCsrfToken('a=1;    chenxing_csrf=abc123')).toBe('abc123')
  })

  it('decodes percent-encoded token values', () => {
    expect(parseCsrfToken('chenxing_csrf=a%2Bb%3Dc')).toBe('a+b=c')
  })

  it('falls back to the raw value when percent-decoding fails', () => {
    // 畸形编码不应让整个请求链路抛异常，原样返回由后端拒绝。
    expect(parseCsrfToken('chenxing_csrf=%E0%A4%A')).toBe('%E0%A4%A')
    expect(parseCsrfToken('chenxing_csrf=100%')).toBe('100%')
  })

  it('returns undefined when the cookie is absent or empty', () => {
    expect(parseCsrfToken('')).toBeUndefined()
    expect(parseCsrfToken('a=1; b=2')).toBeUndefined()
    expect(parseCsrfToken('chenxing_csrf=')).toBeUndefined()
    expect(parseCsrfToken('a=1; chenxing_csrf=; b=2')).toBeUndefined()
  })

  it('does not match cookies that merely contain the name', () => {
    // 前缀匹配必须锚定在 cookie 名开头，否则攻击者可用 x_chenxing_csrf 顶替。
    expect(parseCsrfToken('not_chenxing_csrf=evil')).toBeUndefined()
    expect(parseCsrfToken('xchenxing_csrf=evil')).toBeUndefined()
    expect(parseCsrfToken('other=chenxing_csrf=evil')).toBeUndefined()
  })

  it('picks the first matching cookie when duplicates exist', () => {
    expect(parseCsrfToken('chenxing_csrf=first; chenxing_csrf=second')).toBe('first')
  })

  it('prefers the secure cookie when both names are present', () => {
    expect(parseCsrfToken('chenxing_csrf=local; __Host-chenxing_csrf=secure')).toBe('secure')
  })
})

describe('safeErrorMessage', () => {
  it('prefers the mapped message for known codes', () => {
    expect(safeErrorMessage(401, 'invalid_credentials')).toBe('账号或密码不正确。')
    expect(safeErrorMessage(400, 'passkey_disabled')).toBe('Passkey 登录尚未启用。')
    expect(safeErrorMessage(404, 'invitation_code_not_found')).toBe('邀请码不存在或已失效。')
    expect(safeErrorMessage(500, 'csrf_invalid')).toBe('请求校验失败，请刷新页面后重试。')
  })

  it('falls back to status text for unknown or missing codes', () => {
    expect(safeErrorMessage(400)).toBe('请求参数不正确，请检查输入。')
    expect(safeErrorMessage(401)).toBe('登录状态已失效，请重新登录。')
    expect(safeErrorMessage(403)).toBe('当前账号没有执行此操作的权限。')
    expect(safeErrorMessage(404)).toBe('请求的资源不存在或已失效。')
    expect(safeErrorMessage(409)).toBe('请求与当前数据冲突，请刷新后重试。')
    expect(safeErrorMessage(429)).toBe('操作过于频繁，请稍后重试。')
    expect(safeErrorMessage(500)).toBe('服务暂时不可用，请稍后重试。')
    expect(safeErrorMessage(503)).toBe('服务暂时不可用，请稍后重试。')
    expect(safeErrorMessage(418)).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(0)).toBe(SAFE_FALLBACK)
  })

  it('ignores unknown codes instead of echoing them', () => {
    // 错误码来自后端响应体，不能被当作文案拼进界面。
    expect(safeErrorMessage(400, 'sql_error_at_users_table')).toBe('请求参数不正确，请检查输入。')
    expect(safeErrorMessage(200, 'totally_unknown_code')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(400, '')).toBe('请求参数不正确，请检查输入。')
  })

  it('returns a safe string for prototype keys (regression for #97)', () => {
    // 查表改成 Map 之前，'constructor' 会返回 Object 构造函数，React 渲染它会整页崩溃。
    for (const code of POLLUTION_KEYS) {
      const message = safeErrorMessage(500, code)
      expect(typeof message).toBe('string')
      expect(typeof message).not.toBe('function')
      expect(message).toBe('服务暂时不可用，请稍后重试。')
    }
    expect(safeErrorMessage(200, 'constructor')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(200, '__proto__')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(200, 'toString')).toBe(SAFE_FALLBACK)
  })
})

describe('externalLoginErrorMessage', () => {
  it('maps known codes and defaults the rest', () => {
    expect(externalLoginErrorMessage('oauth_provider_not_found')).toBe('该外部身份源不可用或已被停用。')
    expect(externalLoginErrorMessage('oauth_login_rate_limited')).toBe('外部登录尝试过于频繁，请稍后重试。')
    expect(externalLoginErrorMessage('whatever')).toBe('外部身份源登录未完成，请重试。')
    expect(externalLoginErrorMessage('')).toBe('外部身份源登录未完成，请重试。')
  })

  it('returns a safe string for prototype keys (regression for #97)', () => {
    // 该 code 直接来自 URL 查询参数，是 #97 最容易被外部触达的入口。
    for (const code of POLLUTION_KEYS) {
      const message = externalLoginErrorMessage(code)
      expect(typeof message).toBe('string')
      expect(message).toBe('外部身份源登录未完成，请重试。')
    }
  })
})

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

describe('apiFetch', () => {
  let fetchMock: FetchMock

  beforeEach(() => {
    fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)
    // __Host- 前缀要求 Secure 属性，缺了它 tough-cookie 会静默丢弃，清不掉残留 cookie。
    document.cookie = '__Host-chenxing_csrf=; Secure; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    document.cookie = 'chenxing_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    // 401 重定向的 returnTo 取自当前地址：固定起点让用例互不影响。
    replaceUrl('/')
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('parses a JSON body and always sends credentials', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: { authenticated: true } }))
    await expect(apiFetch<{ authenticated: boolean }>('/api/v1/auth/status'))
      .resolves.toEqual({ authenticated: true })
    expect(fetchMock.mock.calls[0][1]?.credentials).toBe('include')
    expect(headersOf(fetchMock).get('Accept')).toBe('application/json')
  })

  it('wraps invalid JSON from a successful response in a safe ApiError', async () => {
    fetchMock.mockResolvedValue(stubResponse({
      status: 200,
      jsonThrows: true,
      jsonError: new SyntaxError('Unexpected token < in JSON'),
    }))

    const error = await apiFetch('/api/v1/health').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 200, message: SAFE_FALLBACK })
    expect((error as ApiError).message).not.toContain('Unexpected token')
  })

  it('returns undefined for 204 responses without parsing a body', async () => {
    // 204 没有 body，调用 response.json() 会抛错，必须提前短路。
    document.cookie = 'chenxing_csrf=token-abc'
    const json = vi.fn(() => Promise.reject(new Error('unexpected json parse')))
    fetchMock.mockResolvedValue({ ok: true, status: 204, json } as unknown as Response)
    await expect(apiFetch<void>('/api/v1/auth/logout', { method: 'POST' })).resolves.toBeUndefined()
    expect(json).not.toHaveBeenCalled()
  })

  it('omits the CSRF header on the default GET and every safe method', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: { authenticated: false } }))
    await apiFetch('/api/v1/auth/status')
    await apiFetch('/api/v1/auth/status', { method: 'head' })
    await apiFetch('/api/v1/auth/status', { method: ' OPTIONS ' })
    await apiFetch('/api/v1/auth/status', { method: 'trace' })
    expect(fetchMock).toHaveBeenCalledTimes(4)
    expect(headersOf(fetchMock, 0).get('X-CSRF-Token')).toBeNull()
    expect(headersOf(fetchMock, 0).get('Content-Type')).toBeNull()
    expect(headersOf(fetchMock, 1).get('X-CSRF-Token')).toBeNull()
    expect(headersOf(fetchMock, 2).get('X-CSRF-Token')).toBeNull()
    expect(headersOf(fetchMock, 3).get('X-CSRF-Token')).toBeNull()
  })

  it('sends the CSRF header from the cookie on state changing methods', async () => {
    document.cookie = 'chenxing_csrf=token-abc'
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: {} }))
    await apiFetch('/api/v1/auth/login', { method: 'post', body: '{}' })
    const headers = headersOf(fetchMock)
    expect(headers.get('X-CSRF-Token')).toBe('token-abc')
    expect(headers.get('Content-Type')).toBe('application/json')
  })

  it('prefers the production __Host- cookie over the legacy fallback name', async () => {
    // 两条都存在时只能带 __Host- 的值，否则回退名会顶掉生产优先路径（#374）。
    document.cookie = '__Host-chenxing_csrf=secure-token; Secure; path=/'
    document.cookie = 'chenxing_csrf=fallback-token'
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: {} }))
    await apiFetch('/api/v1/auth/login', { method: 'POST', body: '{}' })
    expect(headersOf(fetchMock).get('X-CSRF-Token')).toBe('secure-token')
  })

  it('fails before fetch when a state-changing request has no CSRF cookie', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: {} }))
    const error = await apiFetch('/api/v1/auth/login', { method: 'POST', body: '{}' })
      .catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({
      status: 0,
      code: 'csrf_required',
      message: '请求校验失败，请刷新页面后重试。',
    })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('allows an explicitly marked pre-session request without a CSRF cookie', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: { expires_at: '2099-01-01T00:00:00Z' } }))

    await expect(apiFetch('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ identifier: 'user@example.test', password: 'password' }),
      csrf: 'pre-session',
    })).resolves.toEqual({ expires_at: '2099-01-01T00:00:00Z' })

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(headersOf(fetchMock).get('X-CSRF-Token')).toBeNull()
    expect(fetchMock.mock.calls[0][1]).not.toHaveProperty('csrf')
  })

  it('preserves an explicit CSRF header when the cookie is missing', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: {} }))
    await apiFetch('/api/v1/auth/login', {
      method: 'POST', body: '{}', headers: { 'X-CSRF-Token': 'explicit-token' },
    })
    expect(headersOf(fetchMock).get('X-CSRF-Token')).toBe('explicit-token')
  })

  it('lets the browser set the boundary for FormData bodies', async () => {
    document.cookie = 'chenxing_csrf=token-abc'
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: {} }))
    await apiFetch('/api/v1/upload', { method: 'POST', body: new FormData() })
    const headers = headersOf(fetchMock)
    expect(headers.get('Content-Type')).toBeNull()
    expect(headers.get('X-CSRF-Token')).toBe('token-abc')
  })

  it('wraps transport failures without exposing the underlying error', async () => {
    fetchMock.mockRejectedValue(new Error('connect ECONNREFUSED 10.0.0.7:3000'))
    const error = await apiFetch('/api/v1/auth/status').catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 0, message: '网络连接不可用，请稍后重试。' })
    expect((error as ApiError).message).not.toContain('10.0.0.7')
  })

  it('maps error responses to safe messages and keeps the code', async () => {
    document.cookie = 'chenxing_csrf=token-abc'
    fetchMock.mockResolvedValue(stubResponse({
      status: 400,
      body: { code: 'invalid_credentials', message: 'password hash mismatch for user 42' },
    }))
    const error = await apiFetch('/api/v1/auth/login', { method: 'POST' }).catch((value: unknown) => value)
    expect(error).toBeInstanceOf(ApiError)
    expect(error).toMatchObject({ status: 400, code: 'invalid_credentials', message: '账号或密码不正确。' })
    // 后端 message 可能含内部细节，不能出现在抛给界面的错误里。
    expect((error as ApiError).message).not.toContain('password hash')
  })

  it('ignores a non-string code and an unparsable error body', async () => {
    // code 只接受字符串，对象或缺失都退回状态码文案，避免把结构化数据渲染到界面。
    document.cookie = 'chenxing_csrf=token-abc'
    fetchMock.mockResolvedValue(stubResponse({ status: 409, body: { code: { evil: true } } }))
    const objectCode = await apiFetch('/api/v1/plans', { method: 'POST' }).catch((value: unknown) => value) as ApiError
    expect(objectCode.status).toBe(409)
    expect(objectCode.code).toBeUndefined()
    expect(objectCode.message).toBe('请求与当前数据冲突，请刷新后重试。')

    fetchMock.mockResolvedValue(stubResponse({ status: 500, jsonThrows: true }))
    const noBody = await apiFetch('/api/v1/plans', { method: 'POST' }).catch((value: unknown) => value) as ApiError
    expect(noBody.status).toBe(500)
    expect(noBody.code).toBeUndefined()
    expect(noBody.message).toBe('服务暂时不可用，请稍后重试。')
  })

  it('redirects to the login page on 401 by default', async () => {
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const dispatchEvent = vi.spyOn(window, 'dispatchEvent')
    fetchMock.mockResolvedValue(stubResponse({ status: 401, body: {} }))
    const returnTo = encodeURIComponent(`${window.location.pathname}${window.location.search}`)
    const currentIndex = window.history.state?.[HISTORY_INDEX]

    await expect(apiFetch('/api/v1/auth/me')).rejects.toBeInstanceOf(ApiError)

    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }),
      '',
      `/login?returnTo=${returnTo}`,
    )
    expect(window.history.state?.[HISTORY_INDEX]).toBe(currentIndex)
    // URL replacement has its own render notification; it is not a browser traversal.
    expect(dispatchEvent.mock.calls.some(([event]) => event.type === 'popstate')).toBe(false)
    expect(dispatchEvent.mock.calls.some(([event]) => event.type === NAVIGATION_EVENT)).toBe(true)
  })

  it('hoists request_id out of returnTo when 401 hits an OAuth page (#270)', async () => {
    replaceUrl('/oauth/consent?request_id=req-270')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    fetchMock.mockResolvedValue(stubResponse({ status: 401, body: {} }))

    await expect(apiFetch('/api/v1/oauth/authorize/requests/req-270')).rejects.toBeInstanceOf(ApiError)

    // 登录页只读自己的 request_id 决定登录后是否重新绑定；埋在 returnTo 里读不到，
    // 于是登录成功后直接跳确认页，确认页再次 401 —— 这就是登录循环。
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }),
      '',
      [
        '/login?returnTo=',
        encodeURIComponent('/oauth/consent?request_id=req-270'),
        '&request_id=req-270',
      ].join(''),
    )
  })

  it('does not redirect when redirectOn401 is disabled', async () => {
    // 登录和 Passkey 流程需要就地展示错误，重定向会打断多因素步骤。
    document.cookie = 'chenxing_csrf=token-abc'
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    fetchMock.mockResolvedValue(stubResponse({ status: 401, body: { code: 'invalid_login_ticket' } }))

    await expect(apiFetch('/api/v1/auth/passkeys/authentication/start', {
      method: 'POST', redirectOn401: false,
    })).rejects.toMatchObject({ status: 401, message: '验证流程已失效，请重新登录。' })
    expect(replaceState).not.toHaveBeenCalled()
  })

  it('does not redirect on non-401 failures', async () => {
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    fetchMock.mockResolvedValue(stubResponse({ status: 403, body: {} }))
    await expect(apiFetch('/api/v1/admin/overview')).rejects.toBeInstanceOf(ApiError)
    expect(replaceState).not.toHaveBeenCalled()
  })

  it('does not send redirectOn401 to fetch', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: { authenticated: false } }))
    await apiFetch('/api/v1/auth/status', { redirectOn401: false })
    expect(fetchMock.mock.calls[0][1]).not.toHaveProperty('redirectOn401')
  })

  it('rejects an auth/status response with the wrong field type', async () => {
    fetchMock.mockResolvedValue(stubResponse({ status: 200, body: { authenticated: 'true' } }))

    await expect(apiFetch('/api/v1/auth/status')).rejects.toMatchObject({
      status: 200,
      message: SAFE_FALLBACK,
    })
  })

  it('rejects an auth/me response with an unknown role', async () => {
    fetchMock.mockResolvedValue(stubResponse({
      status: 200,
      body: {
        id: 42,
        username: 'user-42',
        email: 'user@example.test',
        display_name: null,
        status: 'active',
        role: 'superuser',
        current_session_expires_at: '2099-01-01T00:00:00Z',
      },
    }))

    await expect(apiFetch('/api/v1/auth/me')).rejects.toMatchObject({
      status: 200,
      message: SAFE_FALLBACK,
    })
  })

  it('rejects an OAuth pending response with non-array scopes', async () => {
    fetchMock.mockResolvedValue(stubResponse({
      status: 200,
      body: {
        request_id: 'request-1',
        client_id: 'client-1',
        client_name: 'Example App',
        redirect_host: 'client.example.test',
        scopes: 'openid',
        expires_in: 600,
      },
    }))

    await expect(apiFetch('/api/v1/oauth/authorize/requests/request-1')).rejects.toMatchObject({
      status: 200,
      message: SAFE_FALLBACK,
    })
  })
})

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
