import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiFetch } from './api'
import { HISTORY_INDEX, NAVIGATION_EVENT, replaceUrl } from './router'
const SAFE_FALLBACK = '请求未完成，请稍后重试。'
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
