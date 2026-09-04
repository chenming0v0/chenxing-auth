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

  it('refreshes an unauthenticated tab after a remote login event (#665)', async () => {
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      return Promise.resolve(profileCalls === 1
        ? jsonResponse({ code: 'unauthorized' }, 401)
        : jsonResponse(ownerProfile()))
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(profileCalls).toBe(1))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))

    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'chenxing-auth-sync-event',
        newValue: JSON.stringify({ type: 'login', nonce: 'remote-login', occurredAt: Date.now() }),
      }))
    })
    await waitFor(() => expect(profileCalls).toBe(2))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
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

  it('drops an initial refresh that succeeds after a remote logout', async () => {
    let resolveInitial: ((response: Response) => void) | undefined
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      return new Promise<Response>((resolve) => { resolveInitial = resolve })
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(profileCalls).toBe(1))
    expect(screen.getByLabelText('认证状态').textContent).toBe('loading')
    const generationBeforeLogout = screen.getByLabelText('认证代数').textContent

    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'chenxing-auth-sync-event',
        newValue: JSON.stringify({ type: 'logout', nonce: 'remote-initial-logout', occurredAt: Date.now() }),
      }))
    })

    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(screen.getByLabelText('认证代数').textContent).not.toBe(generationBeforeLogout)
    await resolveDeferred(resolveInitial, jsonResponse(ownerProfile('stale-initial')))
    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(screen.getByLabelText('当前用户').textContent).toBe('')
  })

  it('drops a retry refresh that succeeds after a remote logout', async () => {
    let resolveRetry: ((response: Response) => void) | undefined
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      if (profileCalls === 1) return Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
      return new Promise<Response>((resolve) => { resolveRetry = resolve })
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('error'))
    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(profileCalls).toBe(2))
    expect(screen.getByLabelText('认证状态').textContent).toBe('loading')
    const generationBeforeLogout = screen.getByLabelText('认证代数').textContent

    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'chenxing-auth-sync-event',
        newValue: JSON.stringify({ type: 'logout', nonce: 'remote-retry-logout', occurredAt: Date.now() }),
      }))
    })

    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(screen.getByLabelText('认证代数').textContent).not.toBe(generationBeforeLogout)
    await resolveDeferred(resolveRetry, jsonResponse(ownerProfile('stale-retry')))
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

/**
 * 认证事件同时经 BroadcastChannel 和 localStorage 发布，支持两者的标签页会收到两份。
 * 这里用可控的假 BroadcastChannel 精确复现「同一 nonce 双通道交付」，不依赖 jsdom
 * 是否自带 BroadcastChannel 实现（#689）。
 */
type AuthSyncMessage = { type: 'login' | 'logout'; nonce: string; occurredAt: number }
type MessageListener = (event: MessageEvent<AuthSyncMessage>) => void

type FakeChannel = {
  /** AuthProvider 通过该通道发出的事件，按发出顺序。 */
  posted: AuthSyncMessage[]
  /** 模拟其他标签页的 BroadcastChannel 消息到达本标签。 */
  deliver: (data: AuthSyncMessage) => void
}

function installFakeBroadcastChannel(): FakeChannel[] {
  const channels: FakeChannel[] = []
  class StubBroadcastChannel {
    listeners: MessageListener[] = []
    posted: AuthSyncMessage[] = []
    name: string
    constructor(name: string) {
      this.name = name
      channels.push({
        posted: this.posted,
        deliver: (data) => {
          for (const listener of [...this.listeners]) listener({ data } as MessageEvent<AuthSyncMessage>)
        },
      })
    }
    addEventListener(type: string, listener: MessageListener) {
      if (type === 'message') this.listeners.push(listener)
    }
    removeEventListener(type: string, listener: MessageListener) {
      if (type === 'message') this.listeners = this.listeners.filter((entry) => entry !== listener)
    }
    postMessage(data: AuthSyncMessage) { this.posted.push(data) }
    close() { this.listeners = [] }
  }
  vi.stubGlobal('BroadcastChannel', StubBroadcastChannel)
  return channels
}

describe('cross-tab auth event delivery (#689)', () => {
  function stubAuthNetwork(onMe: () => Promise<Response>) {
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/session' && String(init?.method).toUpperCase() === 'DELETE') {
        return Promise.resolve(emptyResponse(204))
      }
      if (path === '/api/v1/auth/me') return onMe()
      throw new Error(`unexpected request: ${path}`)
    }))
  }

  async function deliverOverBothChannels(channel: FakeChannel, event: AuthSyncMessage) {
    await act(async () => {
      channel.deliver(event)
    })
    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', {
        key: 'chenxing-auth-sync-event',
        newValue: JSON.stringify(event),
      }))
    })
  }

  it('refreshes only once when one remote login arrives over both channels', async () => {
    const channels = installFakeBroadcastChannel()
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      return Promise.resolve(profileCalls === 1
        ? jsonResponse({ code: 'unauthorized' }, 401)
        : jsonResponse(ownerProfile()))
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    expect(channels).toHaveLength(1)

    await deliverOverBothChannels(channels[0]!, {
      type: 'login',
      nonce: 'dual-delivery-login',
      occurredAt: Date.now() + 1_000,
    })

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    // 初次 /auth/me（401）+ 远端登录触发的一次 refresh。第二条通道不得再打一次。
    expect(profileCalls).toBe(2)
  })

  it('clears local state only once when one remote logout arrives over both channels', async () => {
    const channels = installFakeBroadcastChannel()
    stubAuthNetwork(() => Promise.resolve(jsonResponse(ownerProfile())))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    const generationBefore = Number(screen.getByLabelText('认证代数').textContent)

    await deliverOverBothChannels(channels[0]!, {
      type: 'logout',
      nonce: 'dual-delivery-logout',
      occurredAt: Date.now() + 1_000,
    })

    expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated')
    expect(Number(screen.getByLabelText('认证代数').textContent)).toBe(generationBefore + 1)
  })

  it('still processes two distinct events that share one occurredAt timestamp', async () => {
    const channels = installFakeBroadcastChannel()
    stubAuthNetwork(() => Promise.resolve(jsonResponse(ownerProfile())))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    const generationBefore = Number(screen.getByLabelText('认证代数').textContent)

    const occurredAt = Date.now() + 1_000
    await act(async () => { channels[0]!.deliver({ type: 'logout', nonce: 'same-ms-a', occurredAt }) })
    await act(async () => { channels[0]!.deliver({ type: 'logout', nonce: 'same-ms-b', occurredAt }) })

    // nonce 不同即两个真实事件，时间戳相等不能把它们折叠成一个。
    expect(Number(screen.getByLabelText('认证代数').textContent)).toBe(generationBefore + 2)
  })

  it('ignores its own broadcast echoed back through either channel', async () => {
    const channels = installFakeBroadcastChannel()
    let profileCalls = 0
    stubAuthNetwork(() => {
      profileCalls += 1
      return Promise.resolve(jsonResponse(ownerProfile()))
    })

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))

    fireEvent.click(screen.getByRole('button', { name: '退出登录' }))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('unauthenticated'))
    const ownLogout = channels[0]!.posted.at(-1)
    expect(ownLogout?.type).toBe('logout')
    const generationAfterLogout = Number(screen.getByLabelText('认证代数').textContent)
    const profileCallsAfterLogout = profileCalls

    await deliverOverBothChannels(channels[0]!, ownLogout!)

    expect(Number(screen.getByLabelText('认证代数').textContent)).toBe(generationAfterLogout)
    expect(profileCalls).toBe(profileCallsAfterLogout)
  })
})
