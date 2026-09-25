/**
 * oauth-app-link.tsx：移动端 App Link 回调落到浏览器时的兜底页。
 * - 路径匹配只接受精确的 /app/<数字>/oauth/callback。
 * - 进入后立即清掉地址栏里的 code/state/error（#196），但原始完整链接保留在
 *   组件状态里，供用户点击原生 <a> 再次触发 App Link。
 * - Android 上若公开端点返回包名，原生锚点改为 intent://；404 或网络失败保持 https，且不导航。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { androidAppLinkIntent } from '../android-intent'
import { AppLinkCallbackPage, matchAppLinkCallback } from './oauth-app-link'
import { HISTORY_INDEX } from '../router'

const ANDROID_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
const DESKTOP_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
// jsdom 默认是 http://localhost。intent 只接受 https，所以 Android 用例换成发行者 host 上的 https 回调。
const CALLBACK = 'https://issuer.example.test/app/7/oauth/callback?code=secret-code&state=xyz'

const originalLocationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function stubUserAgent(userAgent: string) {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(userAgent)
}

function stubLocation(href: string): { assign: ReturnType<typeof vi.fn> } {
  const url = new URL(href)
  const assign = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: {
      href: url.href,
      origin: url.origin,
      protocol: url.protocol,
      host: url.host,
      hostname: url.hostname,
      port: url.port,
      pathname: url.pathname,
      search: url.search,
      hash: url.hash,
      assign,
      replace: vi.fn(),
      reload: vi.fn(),
      toString: () => url.href,
    },
  })
  return { assign }
}

beforeEach(() => {
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalLocationDescriptor) {
    Object.defineProperty(window, 'location', originalLocationDescriptor)
  }
})

describe('matchAppLinkCallback 只接受精确的 App Link 回调路径', () => {
  it('匹配数字 id 的回调路径并返回 id', () => {
    expect(matchAppLinkCallback('/app/1/oauth/callback')).toBe('1')
    expect(matchAppLinkCallback('/app/42/oauth/callback')).toBe('42')
  })

  it('拒绝尾部斜杠、非数字 id 与其他路径', () => {
    expect(matchAppLinkCallback('/app/1/oauth/callback/')).toBeNull()
    expect(matchAppLinkCallback('/app/x/oauth/callback')).toBeNull()
    expect(matchAppLinkCallback('/app/1/oauth')).toBeNull()
    expect(matchAppLinkCallback('/oauth/redirect')).toBeNull()
  })
})

describe('AppLinkCallbackPage 进入时清理敏感 query 并保留原始链接（#196）', () => {
  it('带 code/state 进入：展示成功分支，原生锚点指向原始完整链接，地址栏被清理', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback?code=secret-code&state=xyz')
    const originalHref = window.location.href
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权完成，请返回应用' })).toBeTruthy()
    const anchor = screen.getByRole('link', { name: '打开应用继续' })
    expect(anchor.getAttribute('href')).toBe(originalHref)
    expect(anchor.getAttribute('href')).toContain('code=secret-code')
    expect(anchor.getAttribute('href')).toContain('state=xyz')
    expect(screen.getByRole('link', { name: '返回控制台' }).getAttribute('href')).toBe('/console')
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/app/1/oauth/callback',
    )
  })

  it('带 error 进入：展示错误分支，仍提供返回应用的原生锚点', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback?error=access_denied')
    const originalHref = window.location.href
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权没有完成' })).toBeTruthy()
    expect(screen.getByRole('link', { name: '返回应用' }).getAttribute('href')).toBe(originalHref)
    expect(screen.getByRole('link', { name: '返回控制台' })).toBeTruthy()
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/app/1/oauth/callback',
    )
  })

  it('无查询参数进入：判定为无效回调，不改写地址', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权回调无效' })).toBeTruthy()
    expect(screen.getByRole('link', { name: '返回控制台' }).getAttribute('href')).toBe('/console')
    expect(screen.queryByRole('link', { name: /应用/ })).toBeNull()
    expect(replaceState).not.toHaveBeenCalled()
  })
})

/** 把 fetch 的后续续体排空，避免在包名写回 state 之前就断言 href。 */
async function flushPackageLookup() {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
    await Promise.resolve()
  })
}

describe('AppLinkCallbackPage 在 Android 上把打开应用链接换成 intent://', () => {
  it('端点返回包名时，原生锚点指向 intent URL', async () => {
    stubUserAgent(ANDROID_UA)
    const { assign } = stubLocation(CALLBACK)
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    const fetchMock = vi.fn((_path: string, _init?: RequestInit) =>
      Promise.resolve(jsonResponse({ numeric_app_id: 7, package_name: 'com.example.app' })))
    vi.stubGlobal('fetch', fetchMock)

    render(<AppLinkCallbackPage />)

    await waitFor(() => {
      expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href'))
        .toBe(androidAppLinkIntent(CALLBACK, 'com.example.app'))
    })
    expect(screen.getByRole('link', { name: '打开应用继续' }).tagName).toBe('A')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/oauth/app-links/7',
      expect.objectContaining({ credentials: 'same-origin' }),
    )
    expect(assign).not.toHaveBeenCalled()
    expect(replaceState.mock.calls.map((call) => call[2])).toEqual(['/app/7/oauth/callback'])
  })

  it('端点 404 时保持 https 链接，且不导航', async () => {
    stubUserAgent(ANDROID_UA)
    const { assign } = stubLocation(CALLBACK)
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse({ code: 'app_link_not_found' }, 404))))

    render(<AppLinkCallbackPage />)
    await flushPackageLookup()

    expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href')).toBe(CALLBACK)
    expect(assign).not.toHaveBeenCalled()
    expect(replaceState.mock.calls.map((call) => call[2])).toEqual(['/app/7/oauth/callback'])
  })

  it('网络失败时保持 https 链接，且不导航', async () => {
    stubUserAgent(ANDROID_UA)
    const { assign } = stubLocation(CALLBACK)
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('offline'))))

    render(<AppLinkCallbackPage />)
    await flushPackageLookup()

    expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href')).toBe(CALLBACK)
    expect(assign).not.toHaveBeenCalled()
  })

  it.each([
    ['缺少 numeric_app_id', { package_name: 'com.example.app' }],
    ['numeric_app_id 对不上', { numeric_app_id: 8, package_name: 'com.example.app' }],
    ['包名不是字符串', { numeric_app_id: 7, package_name: 1 }],
  ])('%s 时不采用包名', async (_label, body) => {
    stubUserAgent(ANDROID_UA)
    const { assign } = stubLocation(CALLBACK)
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(jsonResponse(body))))

    render(<AppLinkCallbackPage />)
    await flushPackageLookup()

    expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href')).toBe(CALLBACK)
    expect(assign).not.toHaveBeenCalled()
  })

  it('非 Android 不请求包名，链接保持 https', () => {
    stubUserAgent(DESKTOP_UA)
    stubLocation(CALLBACK)
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    render(<AppLinkCallbackPage />)

    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href')).toBe(CALLBACK)
  })

  it('无效回调即使在 Android 上也不请求包名', () => {
    stubUserAgent(ANDROID_UA)
    stubLocation('https://issuer.example.test/app/7/oauth/callback')
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)

    render(<AppLinkCallbackPage />)

    expect(fetchMock).not.toHaveBeenCalled()
    expect(screen.getByRole('heading', { name: '授权回调无效' })).toBeTruthy()
  })

  it('卸载后中止尚未返回的包名请求', () => {
    stubUserAgent(ANDROID_UA)
    stubLocation(CALLBACK)
    let signal: AbortSignal | undefined
    vi.stubGlobal('fetch', (_path: string, init?: RequestInit) => {
      signal = init?.signal ?? undefined
      return new Promise(() => {})
    })

    const view = render(<AppLinkCallbackPage />)
    view.unmount()

    expect(signal?.aborted).toBe(true)
  })
})
