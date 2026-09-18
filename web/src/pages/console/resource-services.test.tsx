import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ResourceServicesPage } from './resource-services'
import { installCsrfCookie } from '../../test/csrf-cookie'

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

installCsrfCookie()

type FetchInit = RequestInit & { method?: string }

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function emptyResponse(status = 204): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => undefined } as unknown as Response
}

const PROVIDER = {
  id: '11111111-1111-4111-8111-111111111111',
  slug: 'demo',
  display_name: '示例资源服务',
  issuer: 'https://provider.example.com',
  identifier_label: '账号',
  secret_label: '密码',
  identifier_sensitive: false,
}

const BINDING = {
  id: '22222222-2222-4222-8222-222222222222',
  provider_id: PROVIDER.id,
  issuer: PROVIDER.issuer,
  uid: 'acct-1001',
  account: 'demo-account-1001',
  name: '演示账号',
  status: 'active',
  snapshot: { account: 'demo-account-1001', name: '演示账号', status: 'active' },
  grant_expires_at: '2026-12-17T00:00:00Z',
  access_expires_at: '2026-09-18T12:00:00Z',
  refresh_expires_at: '2026-10-18T00:00:00Z',
}

let routes: Array<{ path: string; method: string; handler: (init?: FetchInit) => Response }>
let calls: Array<{ path: string; method: string; init?: FetchInit }>

function register(path: string, method: string, handler: (init?: FetchInit) => Response) {
  routes.push({ path, method, handler })
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/account/resource-services')
  routes = []
  calls = []
  vi.stubGlobal('crypto', { randomUUID: () => '33333333-3333-4333-8333-333333333333' })
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: FetchInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ path: url, method, init })
    const route = routes.find((item) => item.method === method && item.path === url.split('?')[0])
    return Promise.resolve(route ? route.handler(init) : jsonResponse({ code: 'not_found' }, 404))
  }))
  register('/api/v1/auth/resource-services', 'GET', () => jsonResponse([PROVIDER]))
  register('/api/v1/auth/resource-services/bindings', 'GET', () => jsonResponse([]))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ResourceServicesPage', () => {
  it('renders an available provider and binds with an idempotency key', async () => {
    register('/api/v1/auth/resource-services/bindings', 'POST', () => jsonResponse(BINDING, 201))
    render(<ResourceServicesPage />)
    expect(await screen.findByRole('heading', { name: '资源服务' })).toBeTruthy()
    expect(screen.getByText('示例资源服务')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '绑定' }))
    fireEvent.change(screen.getByLabelText('账号'), { target: { value: 'demo' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'secret-value' } })
    fireEvent.click(screen.getByRole('button', { name: '确认绑定' }))
    expect(await screen.findByText('演示账号')).toBeTruthy()
    const bindCall = calls.find((call) => call.method === 'POST' && call.path.endsWith('/bindings'))
    expect(new Headers(bindCall?.init?.headers).get('Idempotency-Key')).toBe('33333333-3333-4333-8333-333333333333')
  })

  it('unlinks a live binding', async () => {
    routes = []
    register('/api/v1/auth/resource-services', 'GET', () => jsonResponse([PROVIDER]))
    register('/api/v1/auth/resource-services/bindings', 'GET', () => jsonResponse([BINDING]))
    register(`/api/v1/auth/resource-services/bindings/${BINDING.id}`, 'DELETE', () => emptyResponse())
    render(<ResourceServicesPage />)
    expect(await screen.findByText('acct-1001')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '解绑' }))
    fireEvent.click(screen.getByRole('button', { name: '确认解绑' }))
    await waitFor(() => {
      expect(screen.queryByText('acct-1001')).toBeNull()
    })
  })
})
