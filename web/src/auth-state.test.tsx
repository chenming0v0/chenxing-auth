import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './auth-state'
import { clearApiCache, getEntitlements } from './api'
import { installCsrfCookie } from './test/csrf-cookie'

// logout() 走 DELETE /auth/session，缺 CSRF 会在发请求前被 apiFetch 拦住。
installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function emptyResponse(status: number): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => null } as Response
}

function ownerProfile(username = 'owner') {
  return {
    id: 1,
    username,
    email: `${username}@example.test`,
    display_name: 'Owner',
    status: 'active',
    role: 'owner' as const,
    current_session_expires_at: '2099-01-01T00:00:00Z',
    avatar_updated_at: null,
  }
}

function AuthStateProbe() {
  const { status, bootstrap, user, refresh, completeBootstrap, logout, generation } = useAuth()
  return (
    <div>
      <output aria-label="认证状态">{status}</output>
      <output aria-label="引导状态">{bootstrap}</output>
      <output aria-label="当前用户">{user?.username ?? ''}</output>
      <output aria-label="认证代数">{generation}</output>
      <button type="button" onClick={() => void refresh()}>重试认证</button>
      <button type="button" onClick={completeBootstrap}>完成引导</button>
      <button type="button" onClick={() => void logout()}>退出登录</button>
    </div>
  )
}

/** apiFetch 内部还有 fetch / json 两级 await，必须在 act 里排空续体再断言。 */
async function resolveDeferred(
  resolve: ((response: Response) => void) | undefined,
  response: Response,
) {
  await act(async () => {
    resolve?.(response)
  })
}

afterEach(() => {
  cleanup()
  clearApiCache()
  vi.unstubAllGlobals()
  window.history.replaceState({}, '', '/login')
})

describe('AuthProvider recoverable failures (#250)', () => {
  it('moves an initial non-401 /auth/me failure into an error state and can retry', async () => {
    let profileAttempts = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        profileAttempts += 1
        if (profileAttempts === 1) {
          return Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
        }
        return Promise.resolve(jsonResponse(ownerProfile()))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('error'))
    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    expect(profileAttempts).toBe(2)
  })

  it('skips the bootstrap status probe when the server owns document navigation', async () => {
    const requests: string[] = []
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      requests.push(path)
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('引导状态').textContent).toBe('ready')
    expect(requests).toEqual(['/api/v1/auth/me'])
  })

  it('does not probe bootstrap status during normal startup', async () => {
    const requests: string[] = []
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      requests.push(path)
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(requests).toEqual(['/api/v1/auth/me'])
  })

  it('trusts a server-routed bootstrap document until the user completes initialization', async () => {
    window.history.replaceState({}, '', '/bootstrap')
    const requests: string[] = []
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      requests.push(path)
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('引导状态').textContent).toBe('required')
    fireEvent.click(screen.getByRole('button', { name: '完成引导' }))
    expect(screen.getByLabelText('引导状态').textContent).toBe('ready')
    expect(requests).toEqual(['/api/v1/auth/me'])
  })
})

describe('refresh request ordering (#473)', () => {
  function stubAuthNetwork(onMe: () => Promise<Response>) {
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/session' && String(init?.method).toUpperCase() === 'DELETE') {
        return Promise.resolve(emptyResponse(204))
      }
      if (path === '/api/v1/auth/me') return onMe()
      throw new Error(`unexpected request: ${path}`)
    }))
  }

  it('does not let an older 401 clear a newer successful refresh', async () => {
    let resolveOld: ((response: Response) => void) | undefined
    let resolveNew: ((response: Response) => void) | undefined
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      return new Promise<Response>((resolve) => {
        if (profileCalls === 1) resolveOld = resolve
        else resolveNew = resolve
      })
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(profileCalls).toBe(1))
    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(profileCalls).toBe(2))

    await resolveDeferred(resolveNew, jsonResponse(ownerProfile()))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    expect(screen.getByLabelText('当前用户').textContent).toBe('owner')

    await resolveDeferred(resolveOld, jsonResponse({ code: 'unauthorized' }, 401))
    expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated')
    expect(screen.getByLabelText('当前用户').textContent).toBe('owner')
  })

  it('drops a successful refresh that lands after logout', async () => {
    let resolveInFlight: ((response: Response) => void) | undefined
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      if (profileCalls === 1) return Promise.resolve(jsonResponse(ownerProfile()))
      return new Promise<Response>((resolve) => { resolveInFlight = resolve })
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))

    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(profileCalls).toBe(2))

    fireEvent.click(screen.getByRole('button', { name: '退出登录' }))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(screen.getByLabelText('当前用户').textContent).toBe('')

    await resolveDeferred(resolveInFlight, jsonResponse(ownerProfile('stale')))
    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(screen.getByLabelText('当前用户').textContent).toBe('')
  })

  it('clears entitlement cache when refresh switches to a different account (#527)', async () => {
    let profileCalls = 0
    let entitlementCalls = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        profileCalls += 1
        return Promise.resolve(jsonResponse(profileCalls === 1 ? ownerProfile('account-a') : { ...ownerProfile('account-b'), id: 2 }))
      }
      if (path === '/api/v1/auth/entitlements') {
        entitlementCalls += 1
        return Promise.resolve(jsonResponse({
          entitlements: [{ key: 'daily_auth', used: entitlementCalls, limit: 10 }],
        }))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('当前用户').textContent).toBe('account-a'))
    const firstGeneration = screen.getByLabelText('认证代数').textContent
    await act(async () => { await getEntitlements() })

    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(screen.getByLabelText('当前用户').textContent).toBe('account-b'))
    expect(screen.getByLabelText('认证代数').textContent).not.toBe(firstGeneration)
    const entitlements = await getEntitlements()

    expect(entitlementCalls).toBe(2)
    expect(entitlements.entitlements[0]?.used).toBe(2)
  })

  it('does not let an old entitlement response repopulate the new account cache (#527)', async () => {
    let profileCalls = 0
    let entitlementCalls = 0
    let resolveOld: ((response: Response) => void) | undefined
    let resolveNew: ((response: Response) => void) | undefined
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/auth/me') {
        profileCalls += 1
        return Promise.resolve(jsonResponse(profileCalls === 1 ? ownerProfile('account-a') : { ...ownerProfile('account-b'), id: 2 }))
      }
      if (path === '/api/v1/auth/entitlements') {
        entitlementCalls += 1
        return new Promise<Response>((resolve) => {
          if (entitlementCalls === 1) resolveOld = resolve
          else resolveNew = resolve
        })
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('当前用户').textContent).toBe('account-a'))
    const oldRequest = getEntitlements()

    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(screen.getByLabelText('当前用户').textContent).toBe('account-b'))
    const newRequest = getEntitlements()
    await resolveDeferred(resolveNew, jsonResponse({ entitlements: [{ key: 'daily_auth', used: 2, limit: 10 }] }))
    await resolveDeferred(resolveOld, jsonResponse({ entitlements: [{ key: 'daily_auth', used: 1, limit: 10 }] }))
    await oldRequest
    await newRequest

    expect(await getEntitlements()).toEqual({
      entitlements: [{ key: 'daily_auth', used: 2, limit: 10 }],
    })
    expect(entitlementCalls).toBe(2)
  })
})
