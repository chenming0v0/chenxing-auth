import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { loadAuthorizationRequest, safeErrorMessage } from './api'

/** 构造授权请求测试所需的 Response 子集。 */
function stubResponse(init: { status: number; body?: unknown }): Response {
  return {
    ok: init.status >= 200 && init.status < 300,
    status: init.status,
    json: () => Promise.resolve(init.body),
  } as unknown as Response
}

function createFetchMock() {
  return vi.fn((_input: string, _init?: RequestInit): Promise<Response> =>
    Promise.resolve(stubResponse({ status: 200, body: {} })))
}

type FetchMock = ReturnType<typeof createFetchMock>

describe('loadAuthorizationRequest', () => {
  let fetchMock: FetchMock

  beforeEach(() => {
    fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)
    document.cookie = 'chenxing_csrf=token-abc'
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  const PENDING = {
    request_id: 'req-270',
    client_id: 'client-1',
    client_name: 'Example App',
    redirect_host: 'client.example.test',
    scopes: ['openid'],
    expires_in: 600,
  }

  it('先绑定再读取，让新会话接管旧绑定', async () => {
    fetchMock.mockImplementation((_path: string, init?: RequestInit) =>
      Promise.resolve(init?.method === 'POST'
        ? stubResponse({ status: 204 })
        : stubResponse({ status: 200, body: PENDING })))

    await expect(loadAuthorizationRequest('req-270')).resolves.toMatchObject({ request_id: 'req-270' })

    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/oauth/authorize/requests/req-270/bind')
    expect(fetchMock.mock.calls[0][1]?.method).toBe('POST')
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/oauth/authorize/requests/req-270')
  })

  it('绑定失败但读取成功时不打断流程', async () => {
    // holder 缺失等情形下会话可能仍然有效且已绑定，此时读得到就该继续。
    fetchMock.mockImplementation((_path: string, init?: RequestInit) =>
      Promise.resolve(init?.method === 'POST'
        ? stubResponse({ status: 403, body: { code: 'authorization_holder_invalid' } })
        : stubResponse({ status: 200, body: PENDING })))

    await expect(loadAuthorizationRequest('req-270')).resolves.toMatchObject({ request_id: 'req-270' })
  })

  it('两步都失败时抛出绑定错误，因为它更能说明真实原因', async () => {
    fetchMock.mockImplementation((_path: string, init?: RequestInit) =>
      Promise.resolve(init?.method === 'POST'
        ? stubResponse({ status: 400, body: { code: 'authorization_request_expired' } })
        : stubResponse({ status: 401, body: {} })))

    await expect(loadAuthorizationRequest('req-270')).rejects.toMatchObject({
      status: 400,
      code: 'authorization_request_expired',
      message: '授权请求已过期，请重新发起。',
    })
  })

  it('绑定与读取都不自动跳登录页，处置权留给调用方', async () => {
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    fetchMock.mockResolvedValue(stubResponse({ status: 401, body: {} }))

    await expect(loadAuthorizationRequest('req-270')).rejects.toMatchObject({ status: 401 })
    expect(replaceState).not.toHaveBeenCalled()
  })

  it('对新增的绑定错误码给出可读文案', () => {
    expect(safeErrorMessage(409, 'authorization_request_conflict'))
      .toBe('授权请求正在被其他标签页更新，请稍后重试。')
    expect(safeErrorMessage(403, 'authorization_holder_invalid'))
      .toBe('这条授权请求不是在当前浏览器发起的，请回到应用重新开始授权。')
  })
})
