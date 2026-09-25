/**
 * 确认页决策成功后的交接态回归测试。
 *
 * 跳转前抹掉 request_id（#196）会让路由重渲染确认页；旧实现随即以 'no-request'
 * 重挂载并展示「授权请求缺少 request_id」，而服务端其实已签发授权码。回调页加载
 * 慢时用户只能看到这条假错误，误以为授权失败。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { PendingAuthorization } from '../api'
import { installCsrfCookie } from '../test/csrf-cookie'
import { OAuthConsentPage } from './oauth'

installCsrfCookie()

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
  scopes: ['openid'],
  expires_in: 300,
}

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const originalLocationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')

/**
 * 只替换 assign（模拟「跳转已发出、回调页尚未加载」），地址字段仍实时读取真实
 * location，这样 replaceState 抹掉 request_id 后路由器能看到变化，复现重渲染。
 */
function stubAssignKeepingLiveLocation(): ReturnType<typeof vi.fn> {
  const real = window.location
  const assign = vi.fn()
  // jsdom 的 Location 属性不可配置，Proxy 改写 assign 会违反不变式，只能用 getter 转发。
  const live = {
    assign,
    replace: assign,
    reload: vi.fn(),
    get href() { return real.href },
    get origin() { return real.origin },
    get protocol() { return real.protocol },
    get host() { return real.host },
    get hostname() { return real.hostname },
    get port() { return real.port },
    get pathname() { return real.pathname },
    get search() { return real.search },
    get hash() { return real.hash },
    toString: () => real.href,
  }
  Object.defineProperty(window, 'location', { configurable: true, writable: true, value: live })
  return assign
}

beforeEach(() => {
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalLocationDescriptor) Object.defineProperty(window, 'location', originalLocationDescriptor)
})

describe('OAuthConsentPage 决策成功后的交接态', () => {
  it.each([
    ['允许', 'approve', '授权完成 · 正在返回接入应用'],
    ['取消', 'deny', '已取消授权 · 正在返回接入应用'],
  ])('点击%s后展示正在返回，而不是「缺少 request_id」', async (button, decision, heading) => {
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    const assign = stubAssignKeepingLiveLocation()
    vi.stubGlobal('fetch', (_path: string, init?: RequestInit) => {
      if (init?.method === 'POST' && String(init.body).includes('decision')) {
        return Promise.resolve(jsonResponse({ decision, redirect_to: 'https://client.example.com/cb?state=xyz' }))
      }
      if (init?.method === 'POST') return Promise.resolve(jsonResponse(null, 204))
      return Promise.resolve(jsonResponse(PENDING))
    })

    render(<OAuthConsentPage />)
    fireEvent.click(await screen.findByRole('button', { name: button }))

    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://client.example.com/cb?state=xyz'))
    expect(window.location.search).toBe('')
    expect(await screen.findByText(heading)).toBeTruthy()
    expect(screen.queryByText('授权请求缺少 request_id，请重新发起。')).toBeNull()
  })

  function renderApprove(userAgent: string, redirectTo: string, androidPackage: string | null) {
    vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(userAgent)
    window.history.replaceState({}, '', '/oauth/consent?request_id=req-123')
    const assign = stubAssignKeepingLiveLocation()
    vi.stubGlobal('fetch', (_path: string, init?: RequestInit) => {
      if (init?.method === 'POST' && String(init.body).includes('decision')) {
        return Promise.resolve(jsonResponse({ decision: 'approve', redirect_to: redirectTo }))
      }
      if (init?.method === 'POST') return Promise.resolve(jsonResponse(null, 204))
      return Promise.resolve(jsonResponse({ ...PENDING, android_package: androidPackage }))
    })
    render(<OAuthConsentPage />)
    return assign
  }

  it('Android 且带包名时，交接态仍是正在返回，assign 的是 intent URL', async () => {
    const redirectTo = 'https://issuer.example.test/app/7/oauth/callback?code=secret&state=xyz'
    const assign = renderApprove(
      'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
      redirectTo,
      'com.example.app',
    )
    fireEvent.click(await screen.findByRole('button', { name: '允许' }))

    const intent = `intent://issuer.example.test/app/7/oauth/callback?code=secret&state=xyz#Intent;scheme=https;package=com.example.app;S.browser_fallback_url=${encodeURIComponent(redirectTo)};end`
    await waitFor(() => expect(assign).toHaveBeenCalledWith(intent))
    expect(window.location.search).toBe('')
    expect(await screen.findByText('授权完成 · 正在返回接入应用')).toBeTruthy()
    expect(screen.queryByText('授权请求缺少 request_id，请重新发起。')).toBeNull()
  })

  it('非 Android 即使带 android_package 也 assign https', async () => {
    const redirectTo = 'https://issuer.example.test/app/7/oauth/callback?code=secret&state=xyz'
    const assign = renderApprove(
      'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      redirectTo,
      'com.example.app',
    )
    fireEvent.click(await screen.findByRole('button', { name: '允许' }))

    await waitFor(() => expect(assign).toHaveBeenCalledWith(redirectTo))
    expect(await screen.findByText('授权完成 · 正在返回接入应用')).toBeTruthy()
  })

  it('原本就没有 request_id 时仍提示缺少参数', async () => {
    window.history.replaceState({}, '', '/oauth/consent')
    vi.stubGlobal('fetch', () => Promise.resolve(jsonResponse(PENDING)))

    render(<OAuthConsentPage />)

    expect(await screen.findByText('授权请求缺少 request_id，请重新发起。')).toBeTruthy()
  })
})
