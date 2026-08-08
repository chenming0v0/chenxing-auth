import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { AuthProvider, useAuth } from './auth-state'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function AuthStateProbe() {
  const { status, refresh } = useAuth()
  return (
    <div>
      <output aria-label="认证状态">{status}</output>
      <button type="button" onClick={() => void refresh()}>重试认证</button>
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
