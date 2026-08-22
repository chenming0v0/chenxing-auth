/**
 * oauth.tsx 的安全相关行为测试（#196 / #199）：
 * - 确认页跳转第三方前，必须先把地址栏与历史里的 request_id 换成无查询版本，
 *   堵住 Referer 与浏览器历史两条泄露路径；无效跳转目标不得改写地址（流程保持可用）。
 * - 回调结果页进入后立即清掉 code/state/error 等敏感 query，且结果分支展示不受影响。
 * - 确认页必须展示服务端校验的 redirect_host / client_id 作为不可伪造身份锚点，
 *   与应用名（可被自定义）清晰分层。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { PendingAuthorization } from '../api'
import { installCsrfCookie } from '../test/csrf-cookie'
import { OAuthAccountPage, OAuthConsentPage, OAuthRedirectPage } from './oauth'
import { HISTORY_INDEX } from '../router'

// 确认页的绑定与决策都是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

// OAuthConsentPage 依赖 useAuth 提供当前用户；mock 掉 auth-state，
// 避免 AuthProvider 挂载时额外发出 /auth/me 请求。
vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: {
      id: 1, username: 'chenxing', email: 'user@chenxing.star', display_name: '辰星',
      status: 'active', role: 'user', current_session_expires_at: '2099-01-01T00:00:00Z',
      avatar_updated_at: null,
    },
    status: 'authenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    clear: () => {},
    logout: () => Promise.resolve(),
  }),
}))

const PENDING: PendingAuthorization = {
  request_id: 'req-123',
  client_id: 'client-abc-456',
  client_name: '示例应用',
  redirect_host: 'client.example.com',
  scopes: ['openid', 'profile'],
  expires_in: 300,
}

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

/** jsdom 的 location.assign 会触发未实现的导航告警，测试里换成可断言的桩。 */
function stubLocationAssign(): ReturnType<typeof vi.fn> {
  const assign = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: {
      href: window.location.href,
      origin: window.location.origin,
      protocol: window.location.protocol,
      host: window.location.host,
      hostname: window.location.hostname,
      port: window.location.port,
      pathname: window.location.pathname,
      search: window.location.search,
      hash: window.location.hash,
      assign,
      replace: assign,
      reload: vi.fn(),
      toString: () => window.location.href,
    },
  })
  return assign
}

const originalLocationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')

beforeEach(() => {
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalLocationDescriptor) {
    Object.defineProperty(window, 'location', originalLocationDescriptor)
  } else {
    delete (window as { location?: unknown }).location
  }
})

describe('OAuthConsentPage 跳转第三方前清理 request_id（#196）', () => {
  it('允许后先抹掉地址与历史中的 request_id，再跳转到回调地址', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    const assign = stubLocationAssign()
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ decision: 'approve', redirect_to: 'https://client.example.com/cb?code=secret-code&state=xyz' }))
      }
      return Promise.resolve(jsonResponse(PENDING))
    })

    render(<OAuthConsentPage />)
    fireEvent.click(await screen.findByRole('button', { name: '允许' }))

    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://client.example.com/cb?code=secret-code&state=xyz'))
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/oauth/consent',
    )
  })

  it('拒绝时同样在跳转前抹掉 request_id', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    const assign = stubLocationAssign()
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ decision: 'deny', redirect_to: 'https://client.example.com/cb?error=access_denied&state=xyz' }))
      }
      return Promise.resolve(jsonResponse(PENDING))
    })

    render(<OAuthConsentPage />)
    fireEvent.click(await screen.findByRole('button', { name: '取消' }))

    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://client.example.com/cb?error=access_denied&state=xyz'))
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/oauth/consent',
    )
  })

  it('跳转地址无效时不改写地址，便于重新发起授权', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    const assign = stubLocationAssign()
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ decision: 'approve', redirect_to: 'javascript:alert(1)' }))
      }
      return Promise.resolve(jsonResponse(PENDING))
    })

    render(<OAuthConsentPage />)
    fireEvent.click(await screen.findByRole('button', { name: '允许' }))

    await waitFor(() => expect(screen.getByText('授权跳转地址无效，已阻止本次跳转，请重新发起授权。')).toBeTruthy())
    expect(replaceState).not.toHaveBeenCalled()
    expect(assign).not.toHaveBeenCalled()
  })
})

describe('OAuthAccountPage 使用其他辰星通行证保留 request_id（#224）', () => {
  it('跳转登录页时保留当前 request_id，并只编码一次', async () => {
    const requestId = 'req/with?reserved=1&provider=github'
    const encodedRequestId = encodeURIComponent(requestId)
    window.history.replaceState({}, '', `/oauth/account?request_id=${encodedRequestId}`)
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse(PENDING)))

    render(<OAuthAccountPage />)

    const link = await screen.findByRole('link', { name: /使用其他辰星通行证/ })
    expect(link.getAttribute('href')).toBe(`/login?request_id=${encodedRequestId}`)
    fireEvent.click(link)

    expect(window.location.pathname).toBe('/login')
    expect(window.location.search).toBe(`?request_id=${encodedRequestId}`)
  })
})

describe('OAuthRedirectPage 进入时清理敏感 query（#196）', () => {
  it('带 error 进入：先固化错误分支，再把地址换成无查询版本', () => {
    window.history.replaceState({}, '', '/oauth/redirect?error=access_denied')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<OAuthRedirectPage />)

    expect(screen.getByRole('heading', { name: '授权没有完成' })).toBeTruthy()
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/oauth/redirect',
    )
  })

  it('带 code/state 进入：仍按成功分支展示，并清掉敏感参数', () => {
    window.history.replaceState({}, '', '/oauth/redirect?code=secret-code&state=xyz')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<OAuthRedirectPage />)

    expect(screen.getByText('授权回调已收到')).toBeTruthy()
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/oauth/redirect',
    )
  })

  it('无查询参数时不做无谓改写', () => {
    window.history.replaceState({}, '', '/oauth/redirect')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<OAuthRedirectPage />)

    expect(replaceState).not.toHaveBeenCalled()
  })
})

describe('OAuthConsentPage 不可伪造身份锚点（#199）', () => {
  it('渲染服务端校验的接入域名与 Client ID，独立成组、与应用名分层', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse(PENDING)))

    render(<OAuthConsentPage />)

    expect(await screen.findByRole('heading', { name: /「示例应用」想要访问你的辰星通行证/ })).toBeTruthy()
    const identity = screen.getByRole('group', { name: /接入应用身份/ })
    expect(identity.textContent).toContain('client.example.com')
    expect(identity.textContent).toContain('client-abc-456')
    // 锚点独立于可自定义的应用名：组内不得混入 client_name
    expect(identity.textContent).not.toContain('示例应用')
  })

  it('信任提示以不可伪造的接入域名为准，并说明应用名可被自定义', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse(PENDING)))

    render(<OAuthConsentPage />)

    await screen.findByRole('group', { name: /接入应用身份/ })
    expect(screen.getByText(/正是你要授权的应用/)).toBeTruthy()
    expect(screen.getByText(/应用名称可被自定义/)).toBeTruthy()
  })
})

/**
 * #270：确认页的会话恢复。
 *
 * 页面在读取待授权请求之前先做一次幂等绑定，让会话过期重登或切换账号后的
 * 新会话接管旧绑定；确实没有会话时带着 request_id 跳一次登录页，
 * 而不是丢掉 request_id 在登录页与确认页之间打转。
 */
describe('OAuthConsentPage 会话恢复与登录跳转（#270）', () => {
  // bind 是状态变更请求，需要 CSRF cookie 才能发出；本文件已通过 installCsrfCookie() 显式注入。
  it('读取待授权请求前先绑定当前会话', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-270')
    const calls: Array<{ path: string; method?: string }> = []
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      calls.push({ path, method: init?.method })
      if (init?.method === 'POST') return Promise.resolve({ ok: true, status: 204, json: async () => undefined } as Response)
      return Promise.resolve(jsonResponse(PENDING))
    })

    render(<OAuthConsentPage />)
    await screen.findByRole('group', { name: /接入应用身份/ })

    expect(calls[0]).toEqual({ path: '/api/v1/oauth/authorize/requests/req-270/bind', method: 'POST' })
    expect(calls[1]).toEqual({ path: '/api/v1/oauth/authorize/requests/req-270', method: undefined })
  })

  it('会话过期重登后新会话接管旧绑定，确认页正常渲染而不跳登录页', async () => {
    // 桩模拟服务端语义：pending 记录还指着旧会话时读取返回 401；
    // bind 通过 holder 校验把它重绑到当前会话之后，读取才成功。
    // 没有「先绑后读」这一步，页面会直接吃到 401 并跳走 —— 也就是 #270 的循环。
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-270')
    let boundToCurrentSession = false
    vi.stubGlobal('fetch', (_path: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        boundToCurrentSession = true
        return Promise.resolve({ ok: true, status: 204, json: async () => undefined } as Response)
      }
      return Promise.resolve(boundToCurrentSession
        ? jsonResponse(PENDING)
        : jsonResponse({ code: 'invalid_session' }, 401))
    })

    render(<OAuthConsentPage />)

    expect(await screen.findByRole('button', { name: '允许' })).toBeTruthy()
    expect(window.location.pathname).toBe('/oauth/consent')
  })

  it('确实没有会话时带着 request_id 跳登录页，不丢参数', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-270')
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse({ code: 'invalid_session' }, 401)))

    render(<OAuthConsentPage />)

    await waitFor(() => expect(window.location.pathname).toBe('/login'))
    const params = new URLSearchParams(window.location.search)
    expect(params.get('request_id')).toBe('req-270')
    expect(params.get('returnTo')).toBe('/oauth/consent?request_id=req-270')
  })

  it('holder 不匹配等终态错误只展示文案，不跳登录页（避免循环）', async () => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-270')
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse({ code: 'authorization_holder_invalid' }, 403)))

    render(<OAuthConsentPage />)

    expect(await screen.findByText(/不是在当前浏览器发起的/)).toBeTruthy()
    expect(window.location.pathname).toBe('/oauth/consent')
  })
})
