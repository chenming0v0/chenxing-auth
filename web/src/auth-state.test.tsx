import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './auth-state'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function AuthStateProbe() {
  const { status, bootstrap, refresh, refreshBootstrap } = useAuth()
  return (
    <div>
      <output aria-label="认证状态">{status}</output>
      <output aria-label="引导状态">{bootstrap}</output>
      <button type="button" onClick={() => void refresh()}>重试认证</button>
      <button type="button" onClick={() => void refreshBootstrap()}>重试引导</button>
    </div>
  )
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('AuthProvider recoverable failures (#250)', () => {
  it('moves an initial non-401 /auth/me failure into an error state and can retry', async () => {
    let profileAttempts = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/admin/bootstrap/status') {
        return Promise.resolve(jsonResponse({ initialized: true }))
      }
      if (path === '/api/v1/auth/me') {
        profileAttempts += 1
        if (profileAttempts === 1) {
          return Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
        }
        return Promise.resolve(jsonResponse({
          id: 1,
          username: 'owner',
          email: 'owner@example.test',
          display_name: 'Owner',
          status: 'active',
          role: 'owner',
          current_session_expires_at: '2099-01-01T00:00:00Z',
          avatar_updated_at: null,
        }))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('error'))
    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))
    expect(profileAttempts).toBe(2)
  })
})

describe('refreshBootstrap failure semantics (#324)', () => {
  it('keeps a transient 5xx recoverable instead of locking out an uninitialized system', async () => {
    let statusAttempts = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/admin/bootstrap/status') {
        statusAttempts += 1
        if (statusAttempts === 1) {
          return Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
        }
        return Promise.resolve(jsonResponse({ initialized: false }))
      }
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    // 瞬态 5xx 不得把 bootstrap 误判为 ready/required：进入 error，等待重试。
    await waitFor(() => expect(screen.getByLabelText('引导状态').textContent).toBe('error'))
    fireEvent.click(screen.getByRole('button', { name: '重试引导' }))
    await waitFor(() => expect(screen.getByLabelText('引导状态').textContent).toBe('required'))
    expect(statusAttempts).toBe(2)
  })

  it('treats a network error (status 0) as transient, not as initialized', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new TypeError('network down'))))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('引导状态').textContent).toBe('error'))
  })

  it('maps the hidden 404 of an initialized instance to ready', async () => {
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/admin/bootstrap/status') {
        return Promise.resolve(jsonResponse({ code: 'not_found' }, 404))
      }
      if (path === '/api/v1/auth/me') {
        return Promise.resolve(jsonResponse({ code: 'unauthorized' }, 401))
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)

    await waitFor(() => expect(screen.getByLabelText('引导状态').textContent).toBe('ready'))
  })
})

describe('refresh request ordering (#473)', () => {
  it('does not let an older 401 clear a newer successful refresh', async () => {
    let resolveOld: ((response: Response) => void) | undefined
    let resolveNew: ((response: Response) => void) | undefined
    let profileCalls = 0
    vi.stubGlobal('fetch', vi.fn((path: string) => {
      if (path === '/api/v1/admin/bootstrap/status') {
        return Promise.resolve(jsonResponse({ initialized: true }))
      }
      if (path === '/api/v1/auth/me') {
        profileCalls += 1
        return new Promise<Response>((resolve) => {
          if (profileCalls === 1) resolveOld = resolve
          else resolveNew = resolve
        })
      }
      throw new Error(`unexpected request: ${path}`)
    }))

    render(<AuthProvider><AuthStateProbe /></AuthProvider>)
    await waitFor(() => expect(profileCalls).toBe(1))
    fireEvent.click(screen.getByRole('button', { name: '重试认证' }))
    await waitFor(() => expect(profileCalls).toBe(2))

    resolveNew?.(jsonResponse({
      id: 1,
      username: 'owner',
      email: 'owner@example.test',
      display_name: 'Owner',
      status: 'active',
      role: 'owner',
      current_session_expires_at: '2099-01-01T00:00:00Z',
      avatar_updated_at: null,
    }))
    await waitFor(() => expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated'))

    resolveOld?.(jsonResponse({ code: 'unauthorized' }, 401))
    await new Promise((resolve) => setTimeout(resolve, 0))
    expect(screen.getByLabelText('认证状态').textContent).toBe('authenticated')
  })
})
