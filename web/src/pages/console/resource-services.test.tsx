import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ResourceServicesPage } from './resource-services'
import { formatDate } from '../../data'
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

type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void }

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

/** 替换 beforeEach 的即时 fetch，让指定的绑定列表 GET 挂起或失败。 */
function stubPageFetch(onBindingsGet: () => Response | Promise<Response>, onMutate?: (path: string, method: string) => Response) {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: FetchInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const path = url.split('?')[0]
    calls.push({ path: url, method, init })
    if (method === 'GET' && path === '/api/v1/auth/resource-services') return Promise.resolve(jsonResponse([PROVIDER]))
    if (method === 'GET' && path === '/api/v1/auth/resource-services/bindings') return Promise.resolve(onBindingsGet())
    return Promise.resolve(onMutate ? onMutate(path, method) : jsonResponse({ code: 'not_found' }, 404))
  }))
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

const SNAPSHOT = {
  schema_version: '1',
  issuer: PROVIDER.issuer,
  uid: 'acct-1001',
  account: 'demo-account-1001',
  name: '演示账号',
  status: 'active',
  subscription: { kind: 'expires_at', expires_at: '2026-12-31T23:59:59Z' },
  fields: [
    { key: 'uid', label: 'UID', type: 'text', value: 'acct-1001' },
    { key: 'account_status', label: '账号状态', type: 'status', value: 'active' },
    { key: 'is_subscribed', label: '已订阅', type: 'boolean', value: true },
    { key: 'subscription_expires_at', label: '订阅到期', type: 'datetime', value: '2026-12-31T23:59:59Z' },
    { key: 'remaining_seconds', label: '剩余订阅', type: 'duration', value: 9071999 },
    { key: 'device_status', label: '设备状态', type: 'status', value: 'bound' },
    { key: 'homepage', label: '主页', type: 'url', value: 'https://provider.example.com/user/1001' },
  ],
  fetched_at: '2026-09-18T00:00:00Z',
}

const BINDING = {
  id: '22222222-2222-4222-8222-222222222222',
  provider_id: PROVIDER.id,
  issuer: PROVIDER.issuer,
  uid: 'acct-1001',
  account: 'demo-account-1001',
  name: '演示账号',
  status: 'active',
  snapshot: SNAPSHOT,
  grant_expires_at: '2026-12-17T00:00:00Z',
  access_expires_at: '2026-09-18T12:00:00Z',
  refresh_expires_at: '2026-10-18T00:00:00Z',
}

let routes: Array<{ path: string; method: string; handler: (init?: FetchInit) => Response }>
let calls: Array<{ path: string; method: string; init?: FetchInit }>

function register(path: string, method: string, handler: (init?: FetchInit) => Response) {
  routes.push({ path, method, handler })
}

function registerBindings(bindings: unknown[]) {
  routes = []
  register('/api/v1/auth/resource-services', 'GET', () => jsonResponse([PROVIDER]))
  register('/api/v1/auth/resource-services/bindings', 'GET', () => jsonResponse(bindings))
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/account/resource-services')
  routes = []
  calls = []
  // 只冻结 Date，保留真实定时器，避免 testing-library 的 waitFor 卡死。
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(new Date('2026-09-18T00:00:00Z'))
  vi.stubGlobal('crypto', { randomUUID: () => '33333333-3333-4333-8333-333333333333' })
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: FetchInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ path: url, method, init })
    const route = routes.find((item) => item.method === method && item.path === url.split('?')[0])
    return Promise.resolve(route ? route.handler(init) : jsonResponse({ code: 'not_found' }, 404))
  }))
  registerBindings([])
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
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

  it('renders the account snapshot with account, subscription summary and typed fields', async () => {
    registerBindings([BINDING])
    render(<ResourceServicesPage />)
    // 头部展示提供方给的展示账号；uid 字段按提供方自带 label 渲染，绑定键不单独标成 UID
    expect(await screen.findByText('demo-account-1001')).toBeTruthy()
    expect(screen.getByText('账号')).toBeTruthy()
    expect(screen.getByText('UID')).toBeTruthy()
    expect(screen.getAllByText('acct-1001')).toHaveLength(1)
    expect(screen.getByText('正常')).toBeTruthy()
    expect(screen.getByText('剩余 105 天')).toBeTruthy()
    expect(screen.getByText(`到期 ${formatDate('2026-12-31T23:59:59Z')}`)).toBeTruthy()
    expect(screen.getByText('设备状态')).toBeTruthy()
    expect(screen.getByText('已绑定')).toBeTruthy()
    const homepage = screen.getByRole('link', { name: 'https://provider.example.com/user/1001' })
    expect(homepage.getAttribute('target')).toBe('_blank')
    expect(homepage.getAttribute('rel')).toContain('noopener')
    expect(screen.getByText('最近同步')).toBeTruthy()
    expect(screen.getByText(formatDate('2026-09-18T00:00:00Z'))).toBeTruthy()
    expect(screen.getByText('授权到期')).toBeTruthy()
    expect(screen.getByText(formatDate('2026-12-17T00:00:00Z'))).toBeTruthy()
    // 头部与订阅摘要已经覆盖的字段不再重复列出
    expect(screen.queryByText('账号状态')).toBeNull()
    expect(screen.queryByText('订阅到期')).toBeNull()
    expect(screen.queryByText('剩余订阅')).toBeNull()
  })

  it('shows 未订阅 for a subscription of kind none', async () => {
    registerBindings([{ ...BINDING, snapshot: { ...SNAPSHOT, subscription: { kind: 'none' }, fields: [] } }])
    render(<ResourceServicesPage />)
    expect(await screen.findByText('未订阅')).toBeTruthy()
    expect(screen.queryByText(/剩余 \d+ 天/)).toBeNull()
  })

  it('still renders a binding whose snapshot is partial', async () => {
    registerBindings([{ ...BINDING, name: null, status: null, snapshot: { account: 'demo-account-1001', name: null, status: 'active' } }])
    render(<ResourceServicesPage />)
    expect(await screen.findByText('demo-account-1001')).toBeTruthy()
    expect(screen.getByText('正常')).toBeTruthy()
    // 没有 fields[].uid 时不会把绑定键当 UID 展示
    expect(screen.queryByText('acct-1001')).toBeNull()
    expect(screen.queryByText('UID')).toBeNull()
    expect(screen.queryByText('订阅')).toBeNull()
    expect(screen.queryByText('最近同步')).toBeNull()
    expect(screen.getByText('授权到期')).toBeTruthy()
  })

  it('unlinks a live binding', async () => {
    registerBindings([BINDING])
    register(`/api/v1/auth/resource-services/bindings/${BINDING.id}`, 'DELETE', () => emptyResponse())
    render(<ResourceServicesPage />)
    expect(await screen.findByText('acct-1001')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '解绑' }))
    fireEvent.click(screen.getByRole('button', { name: '确认解绑' }))
    await waitFor(() => {
      expect(screen.queryByText('acct-1001')).toBeNull()
    })
  })

  it('在途列表 GET 返回时不复活已解绑项', async () => {
    let bindingsGets = 0
    const staleList = deferred<Response>()
    stubPageFetch(() => {
      bindingsGets += 1
      return bindingsGets === 1 ? jsonResponse([BINDING]) : staleList.promise
    }, (path, method) => (
      method === 'DELETE' && path === `/api/v1/auth/resource-services/bindings/${BINDING.id}`
        ? emptyResponse()
        : jsonResponse({ code: 'not_found' }, 404)
    ))
    render(<ResourceServicesPage />)
    expect(await screen.findByText('acct-1001')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(bindingsGets).toBe(2))
    fireEvent.click(screen.getByRole('button', { name: '解绑' }))
    fireEvent.click(screen.getByRole('button', { name: '确认解绑' }))
    await waitFor(() => expect(screen.queryByText('acct-1001')).toBeNull())

    await act(async () => {
      staleList.resolve(jsonResponse([BINDING]))
      await staleList.promise
      // apiFetch 还要过 response.json() 和 allSettled。排空后再断言，避免复活发生在断言之后。
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(screen.queryByText('acct-1001')).toBeNull()
    expect(screen.queryByText('demo-account-1001')).toBeNull()
    expect(screen.getByRole('button', { name: '绑定' })).toBeTruthy()
  })

  it('列表刷新失败时保留已显示的绑定', async () => {
    let bindingsGets = 0
    stubPageFetch(() => {
      bindingsGets += 1
      return bindingsGets === 1 ? jsonResponse([BINDING]) : jsonResponse({ code: 'temporarily_unavailable' }, 503)
    })
    render(<ResourceServicesPage />)
    expect(await screen.findByText('demo-account-1001')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '刷新' }))

    expect(await screen.findByRole('button', { name: '重试' })).toBeTruthy()
    expect(screen.getByText('demo-account-1001')).toBeTruthy()
    expect(screen.getByText('acct-1001')).toBeTruthy()
    expect(screen.queryByText('暂无资源服务绑定')).toBeNull()
  })
})
