import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { useEffect, useState } from 'react'
import type { UserMe } from './api'

const routeState = vi.hoisted(() => ({ path: '/login' }))
const mountState = vi.hoisted(() => ({ next: 0 }))
const authState = vi.hoisted(() => ({
  user: null as UserMe | null,
  status: 'unauthenticated' as 'loading' | 'authenticated' | 'unauthenticated' | 'error',
  generation: 0,
}))

vi.mock('./auth-state', () => ({
  AuthProvider: ({ children }: { children: React.ReactNode }) => children,
  useAuth: () => ({
    user: authState.user,
    status: authState.status,
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    clear: () => {},
    logout: () => Promise.resolve({ revoked: true }),
    generation: authState.generation,
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

vi.mock('./pages/console/account', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./pages/console/account')>()),
  ConsoleOverview: () => {
    const [draft, setDraft] = useState('')
    return <input aria-label="账户业务草稿" value={draft} onChange={(event) => setDraft(event.target.value)} />
  },
}))

vi.mock('./pages/oauth-app-link', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./pages/oauth-app-link')>()),
  AppLinkCallbackPage: () => <div data-testid="app-link-callback-page" />,
}))

vi.mock('./pages/not-found', () => ({
  NotFoundPage: () => <div data-testid="not-found-page" />,
}))

import App from './App'

afterEach(() => {
  cleanup()
  routeState.path = '/login'
  mountState.next = 0
  authState.user = null
  authState.status = 'unauthenticated'
  authState.generation = 0
})

describe('真实账户变化继续清理业务页面（#745）', () => {
  function authenticatedAccount(id: number): UserMe {
    return {
      id, username: `account-${id}`, email: `account-${id}@example.test`, display_name: null,
      status: 'active', role: 'user', current_session_expires_at: '2099-01-01T00:00:00Z', avatar_updated_at: null,
    }
  }

  it('切换账户的页面代数变化仍重置账户业务草稿', () => {
    routeState.path = '/console'
    authState.status = 'authenticated'
    authState.user = authenticatedAccount(1)
    window.history.replaceState({}, '', '/console')
    const { rerender } = render(<App />)
    const oldDraft = screen.getByLabelText('账户业务草稿')
    fireEvent.change(oldDraft, { target: { value: '上一个账户的草稿' } })

    authState.user = authenticatedAccount(2)
    authState.generation += 1
    rerender(<App />)

    expect(screen.getByLabelText('账户业务草稿')).not.toBe(oldDraft)
    expect(screen.getByLabelText('账户业务草稿')).toHaveProperty('value', '')
  })

  it('真正登出后不再展示旧业务页面，重新登录也不恢复旧草稿', () => {
    routeState.path = '/console'
    authState.status = 'authenticated'
    authState.user = authenticatedAccount(1)
    window.history.replaceState({}, '', '/console')
    const { rerender } = render(<App />)
    fireEvent.change(screen.getByLabelText('账户业务草稿'), { target: { value: '退出前的草稿' } })

    authState.user = null
    authState.status = 'unauthenticated'
    authState.generation += 1
    rerender(<App />)
    expect(screen.queryByLabelText('账户业务草稿')).toBeNull()

    authState.status = 'authenticated'
    authState.user = authenticatedAccount(2)
    rerender(<App />)
    expect(screen.getByLabelText('账户业务草稿')).toHaveProperty('value', '')
  })
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

describe('App Link 回调与未知路径不再静默弹回首页', () => {
  it('未登录时 /app/<id>/oauth/callback 直接渲染回调页', () => {
    routeState.path = '/app/1/oauth/callback'
    window.history.replaceState({}, '', '/app/1/oauth/callback')
    render(<App />)

    expect(screen.getByTestId('app-link-callback-page')).toBeTruthy()
  })

  it('未知路径渲染 404 页而不是跳回首页', () => {
    routeState.path = '/definitely/unknown'
    window.history.replaceState({}, '', '/definitely/unknown')
    render(<App />)

    expect(screen.getByTestId('not-found-page')).toBeTruthy()
  })
})
