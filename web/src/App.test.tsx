import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useEffect, useState } from 'react'

const routeState = vi.hoisted(() => ({ path: '/login' }))
const mountState = vi.hoisted(() => ({ next: 0 }))

vi.mock('./auth-state', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: () => ({
    user: null,
    status: 'unauthenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    clear: () => {},
    logout: () => Promise.resolve({ revoked: true }),
    generation: 0,
  }),
}))

vi.mock('./router', () => ({
  Navigate: () => null,
  usePathname: () => {
    const [, rerender] = useState(0)
    useEffect(() => {
      const onPopState = () => rerender((value) => value + 1)
      window.addEventListener('popstate', onPopState)
      return () => window.removeEventListener('popstate', onPopState)
    }, [])
    return routeState.path
  },
}))

vi.mock('./pages/auth', () => ({
  AuthPage: ({ mode }: { mode: string }) => {
    const [mountId] = useState(() => ++mountState.next)
    return <div data-testid="auth-page" data-mode={mode} data-mount-id={mountId} />
  },
  BootstrapPage: () => <div />,
}))

import App from './App'

afterEach(() => {
  cleanup()
  routeState.path = '/login'
  mountState.next = 0
})

describe('auth route instance isolation (#528)', () => {
  it('remounts AuthPage when navigating between login and register', async () => {
    window.history.replaceState({}, '', '/login')
    render(<App />)

    const first = screen.getByTestId('auth-page')
    expect(first.dataset.mode).toBe('login')
    const firstMountId = first.dataset.mountId

    routeState.path = '/register'
    window.dispatchEvent(new PopStateEvent('popstate'))

    await waitFor(() => expect(screen.getByTestId('auth-page').dataset.mode).toBe('register'))
    expect(screen.getByTestId('auth-page').dataset.mountId).not.toBe(firstMountId)
  })
})
