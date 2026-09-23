/**
 * #731：/oauth/redirect 把 code/state 收进组件状态后立刻 scrub。
 * 未登录时页面在 loading 就挂上，随后 /api/v1/auth/me 401 会把 AuthProvider
 * 的 generation 从 0 抬到 1。这一页若仍挂在 <Fragment key={generation}> 下，
 * 新实例只能看到空 query，成功回调会被画成「授权回调无效」。
 *
 * 这里走真实 App（真实 AuthProvider + 真实路由），不 mock auth-state。
 * 401 的 clear() 会广播 logout；等到那条同步事件落地，再断言页面仍是成功分支，
 * 且地址栏没有被写回 code。
 */
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import App from '../App'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  window.localStorage.clear()
  window.history.replaceState({}, '', '/')
})

describe('OAuth 回调页不随未登录 401 重挂（#731）', () => {
  it('scrub 之后 generation 递增，仍显示授权回调已收到', async () => {
    let resolveMe: ((response: Response) => void) | undefined
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        return new Promise<Response>((resolve) => {
          resolveMe = resolve
        })
      }
      throw new Error(`unexpected request: ${path}`)
    })
    vi.stubGlobal('fetch', fetchMock)
    window.history.replaceState({}, '', '/oauth/redirect?code=secret-code&state=xyz')

    render(<App />)

    expect(screen.getByText('授权回调已收到')).toBeTruthy()
    expect(window.location.pathname).toBe('/oauth/redirect')
    expect(window.location.search).toBe('')

    await act(async () => {
      resolveMe?.(jsonResponse({ code: 'invalid_session' }, 401))
      await new Promise((resolve) => setTimeout(resolve, 0))
    })

    const syncEvent = window.localStorage.getItem('chenxing-auth-sync-event')
    expect(syncEvent).toContain('"type":"logout"')
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/auth/me',
      expect.objectContaining({ credentials: 'include' }),
    )
    expect(screen.getByText('授权回调已收到')).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '授权回调无效' })).toBeNull()
    expect(screen.queryByText('授权回调无效')).toBeNull()
    expect(window.location.pathname).toBe('/oauth/redirect')
    expect(window.location.search).toBe('')
    expect(window.location.href).not.toContain('secret-code')
  })
})
