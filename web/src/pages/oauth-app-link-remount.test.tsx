/**
 * #723：App Link 回调不是受保护路由，会在 status==='loading' 时挂上并立刻擦掉地址栏。
 * 随后 /api/v1/auth/me 401 走 clear()，generation +1。若本页仍包在这个 key 里，
 * 重挂后 useState 读到的是已擦掉的地址，有效回调会被画成「授权回调无效」。
 *
 * 这里挂真实 App（内部是 auth-state 的 AuthProvider，不 mock）。地址栏上的
 * code/state 必须真的被擦掉，否则重挂后仍能从 URL 读回，测不出这个 bug。
 */
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from '../App'
import { clearApiCache } from '../api'
import { replaceUrl } from '../router'

/** clear() 在 401 时写入的跨标签登出事件。出现即表示本地状态已切到未登录。 */
const AUTH_SYNC_STORAGE_KEY = 'chenxing-auth-sync-event'

const CALLBACK_PATH = '/app/1/oauth/callback'
const CODE = 'secret-code'
const STATE = 'xyz'
const CALLBACK_URL = `${CALLBACK_PATH}?code=${CODE}&state=${STATE}`

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  window.localStorage.removeItem(AUTH_SYNC_STORAGE_KEY)
  replaceUrl('/login')
})

afterEach(() => {
  cleanup()
  clearApiCache()
  vi.unstubAllGlobals()
  window.localStorage.removeItem(AUTH_SYNC_STORAGE_KEY)
  replaceUrl('/login')
})

describe('App Link 回调不随未登录 401 的 generation 重挂（#723）', () => {
  it('擦掉地址栏后，401 把会话清成未登录，「打开应用继续」仍带着原来的 code 和 state', async () => {
    replaceUrl(CALLBACK_URL)
    const originalHref = window.location.href
    expect(originalHref).toContain(`code=${CODE}`)
    expect(originalHref).toContain(`state=${STATE}`)

    let resolveMe: ((response: Response) => void) | undefined
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path !== '/api/v1/auth/me') throw new Error(`unexpected request: ${path}`)
      return new Promise<Response>((resolve) => {
        resolveMe = resolve
      })
    }))

    render(<App />)

    const captured = screen.getByRole('link', { name: '打开应用继续' })
    expect(captured.getAttribute('href')).toBe(originalHref)
    expect(window.location.pathname).toBe(CALLBACK_PATH)
    expect(window.location.search).toBe('')
    expect(new URLSearchParams(window.location.search).get('code')).toBeNull()
    expect(new URLSearchParams(window.location.search).get('state')).toBeNull()
    expect(window.localStorage.getItem(AUTH_SYNC_STORAGE_KEY)).toBeNull()

    const finishMe = resolveMe
    if (!finishMe) throw new Error('/api/v1/auth/me was not requested')
    // apiFetch 在 fetch 之后还要 await response.json()。这两级续体必须在 act 里排空，
    // 后面的断言才落在 clear() 已经把状态改成未登录之后，而不是 401 尚未落地的成功页上。
    await act(async () => {
      finishMe(jsonResponse({ code: 'unauthorized' }, 401))
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    const sync = window.localStorage.getItem(AUTH_SYNC_STORAGE_KEY)
    expect(sync).toBeTruthy()
    expect((JSON.parse(sync ?? '') as { type?: string }).type).toBe('logout')

    const anchor = screen.getByRole('link', { name: '打开应用继续' })
    expect(anchor.getAttribute('href')).toBe(originalHref)
    expect(anchor.getAttribute('href')).toContain(`code=${CODE}`)
    expect(anchor.getAttribute('href')).toContain(`state=${STATE}`)
    expect(screen.getByRole('heading', { name: '授权完成，请返回应用' })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '授权回调无效' })).toBeNull()
    expect(window.location.pathname).toBe(CALLBACK_PATH)
    expect(window.location.search).toBe('')
    expect(window.location.href).not.toContain(CODE)
    expect(window.location.href).not.toContain(`state=${STATE}`)
  })
})
