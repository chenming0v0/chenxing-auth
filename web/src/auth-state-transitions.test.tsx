import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './auth-state'
import { clearApiCache, getEntitlements } from './api'
import { installCsrfCookie } from './test/csrf-cookie'

installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function profile(id: number) {
  return {
    id, username: `account-${id}`, email: `account-${id}@example.test`, display_name: null,
    status: 'active', role: 'user', current_session_expires_at: '2099-01-01T00:00:00Z', avatar_updated_at: null,
  }
}

function Probe() {
  const { status, user, generation, refresh, logout } = useAuth()
  return <>
    <output aria-label="认证状态">{status}</output>
    <output aria-label="当前账户">{user?.id ?? ''}</output>
    <output aria-label="页面代数">{generation}</output>
    <button onClick={() => void refresh()}>刷新会话</button>
    <button onClick={() => void logout()}>退出登录</button>
  </>
}

afterEach(() => {
  cleanup()
  clearApiCache()
  vi.unstubAllGlobals()
  window.localStorage.removeItem('chenxing-auth-sync-event')
  window.history.replaceState({}, '', '/login')
})

describe('认证请求失效与页面身份代数分别维护（#745）', () => {
  it('首次和重复确认未登录均保留页面代数', async () => {
    let calls = 0
    vi.stubGlobal('fetch', vi.fn(() => {
      calls += 1
      return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
    }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('页面代数').textContent).toBe('0')
    expect(window.localStorage.getItem('chenxing-auth-sync-event')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '刷新会话' }))

    await waitFor(() => expect(calls).toBe(2))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('页面代数').textContent).toBe('0')
    expect(window.localStorage.getItem('chenxing-auth-sync-event')).toBeNull()
  })

  it('已有账户的 401 仍递增页面代数并清理账户缓存', async () => {
    let meCalls = 0
    let entitlementCalls = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(++meCalls === 1 ? jsonResponse(profile(1)) : jsonResponse({ code: 'unauthorized' }, 401))
      }
      if (path === '/api/v1/auth/entitlements') {
        return Promise.resolve(jsonResponse({ entitlements: [{ key: 'daily_auth', used: ++entitlementCalls, limit: 10 }] }))
      }
      throw new Error(`unexpected request: ${path}`)
    }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    await act(async () => { await getEntitlements() })

    fireEvent.click(screen.getByRole('button', { name: '刷新会话' }))

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('当前账户').textContent).toBe('')
    expect(screen.getByLabelText('页面代数').textContent).toBe('1')
    await act(async () => { await getEntitlements() })
    expect(entitlementCalls).toBe(2)
  })

  it('首次 401 后显式登出仍使在途登录资料失效并递增页面代数', async () => {
    let meCalls = 0
    let resolveLate!: (response: Response) => void
    const lateResponse = new Promise<Response>((resolve) => { resolveLate = resolve })
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/session') return Promise.resolve(jsonResponse(null, 204))
      if (path === '/api/v1/auth/me') {
        return ++meCalls === 1 ? Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401)) : lateResponse
      }
      throw new Error(`unexpected request: ${path}`)
    }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    fireEvent.click(screen.getByRole('button', { name: '刷新会话' }))
    await waitFor(() => expect(meCalls).toBe(2))
    fireEvent.click(screen.getByRole('button', { name: '退出登录' }))
    await waitFor(() => expect(screen.getByLabelText('页面代数').textContent).toBe('1'))

    await act(async () => {
      resolveLate(jsonResponse(profile(1)))
      await lateResponse
    })

    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(screen.getByLabelText('当前账户').textContent).toBe('')
    expect(screen.getByLabelText('页面代数').textContent).toBe('1')
  })

  it('首次 401 后登录再切账户，页面代数只反映真实账户变化并清理缓存', async () => {
    let meCalls = 0
    let entitlementCalls = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        meCalls += 1
        return Promise.resolve(meCalls === 1 ? jsonResponse({ code: 'unauthorized' }, 401) : jsonResponse(profile(meCalls - 1)))
      }
      if (path === '/api/v1/auth/entitlements') {
        return Promise.resolve(jsonResponse({ entitlements: [{ key: 'daily_auth', used: ++entitlementCalls, limit: 10 }] }))
      }
      throw new Error(`unexpected request: ${path}`)
    }))
    render(<AuthProvider><Probe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    fireEvent.click(screen.getByRole('button', { name: '刷新会话' }))
    await waitFor(() => expect(screen.getByLabelText('当前账户').textContent).toBe('1'))
    expect(screen.getByLabelText('页面代数').textContent).toBe('0')
    await act(async () => { await getEntitlements() })

    fireEvent.click(screen.getByRole('button', { name: '刷新会话' }))

    await waitFor(() => expect(screen.getByLabelText('当前账户').textContent).toBe('2'))
    expect(screen.getByLabelText('页面代数').textContent).toBe('1')
    await act(async () => { await getEntitlements() })
    expect(entitlementCalls).toBe(2)
  })
})
