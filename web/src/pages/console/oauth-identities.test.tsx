import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { OAuthIdentitiesPage } from './oauth-identities'

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

type FetchInit = RequestInit & { method?: string }

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

/** 模拟服务端 DELETE 204 无返回体，且 apiFetch 内部会先读 JSON——测试用最小桩。 */
function emptyResponse(status = 204): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => undefined } as unknown as Response
}

const OAUTH_ACCOUNT = {
  id: 'oauth_github',
  kind: 'oauth_identity',
  provider: { id: 'github', name: 'GitHub', icon_url: null },
  uid: null,
  subject_hint: 'gh-subject-42',
  display: { name: 'octocat', email: 'octocat@example.com', avatar_url: 'https://avatars.example.test/octocat.png' },
  account_status: 'active',
  linked_at: '2026-09-01T08:00:00Z',
  capabilities: { can_login: true, can_refresh: false },
  sync: {
    status: 'success',
    last_attempt_at: '2026-09-05T08:00:00Z',
    last_success_at: '2026-09-05T08:00:00Z',
    stale_after: null,
    refresh_after: null,
    error: null,
  },
  extensions: [{
    namespace: 'cltermux',
    version: '1',
    fetched_at: '2026-09-05T08:00:00Z',
    fields: [
      { key: 'uid', label: 'CLtermux UID', type: 'text', value: 'cltermux:123' },
      { key: 'remaining_days_oauth', label: '剩余订阅', type: 'duration_days', value: 42 },
      { key: 'subscribed', label: '是否订阅', type: 'boolean', value: true },
      { key: 'raw', label: '未知字段', type: 'vendor_blob', value: { unsafe: '<script>' } },
    ],
  }],
}

const SERVICE_ACCOUNT = {
  id: 'linked_cltermux_1',
  kind: 'service_account',
  provider: { id: 'cltermux', name: 'CLtermux', icon_url: null },
  uid: 'cltermux:sub-001',
  subject_hint: 'cl-subject-9',
  display: { name: 'CLtermux 用户', email: 'cltermux@example.com', avatar_url: null },
  account_status: 'active',
  linked_at: '2026-09-03T08:00:00Z',
  capabilities: { can_login: true, can_refresh: true },
  sync: {
    status: 'success',
    last_attempt_at: '2026-09-05T08:00:00Z',
    last_success_at: '2026-09-05T08:00:00Z',
    stale_after: null,
    refresh_after: null,
    error: null,
  },
  extensions: [{
    namespace: 'cltermux',
    version: '2',
    fetched_at: '2026-09-05T08:00:00Z',
    fields: [
      { key: 'remaining_days', label: '剩余订阅', type: 'duration_days', value: 42 },
    ],
  }],
}

const PROVIDER = {
  id: 'cltermux',
  name: 'CLtermux',
  icon_url: null,
  kind: 'service_account',
  binding_method: 'credentials',
  can_refresh: true,
}

type RouteKey = string
let routes: Array<{
  path: string
  method: string
  handler: (init?: FetchInit) => Promise<Response> | Response
}>
let calls: Array<{ path: string; method: string; init?: FetchInit }> = []

function register(path: string, method: string, handler: (init?: FetchInit) => Promise<Response> | Response) {
  routes.push({ path, method, handler })
}

function fetchStub() {
  return vi.fn((input: RequestInfo | URL, init?: FetchInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const key = `${method} ${url.split('?')[0]}`
    calls.push({ path: url, method, init })
    for (const route of routes) {
      if (`${route.method} ${route.path}` === key) {
        return Promise.resolve(route.handler(init))
      }
    }
    // 未知路径返回 404，便于 guard 路径测试
    return Promise.resolve(jsonResponse({ code: 'not_found' }, 404))
  })
}

function setCsrfCookie(): void {
  document.cookie = 'chenxing_csrf=test-csrf-token'
}

function clearCsrfCookie(): void {
  document.cookie = 'chenxing_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/account/oauth-identities')
  routes = []
  calls = []
  clearCsrfCookie()
  vi.stubGlobal('fetch', fetchStub())
})

afterEach(() => {
  cleanup()
  clearCsrfCookie()
  vi.unstubAllGlobals()
})

function seedRoutes(options: {
  accounts?: unknown[]
  nextCursor?: string | null
  providers?: unknown[]
  accountsError?: Response
} = {}) {
  const {
    accounts = [OAUTH_ACCOUNT, SERVICE_ACCOUNT],
    nextCursor = null,
    providers = [PROVIDER],
    accountsError,
  } = options
  if (accountsError) {
    register('/api/v1/auth/linked-accounts', 'GET', () => accountsError)
  } else {
    register('/api/v1/auth/linked-accounts', 'GET', () => jsonResponse({ items: accounts, next_cursor: nextCursor }))
  }
  register('/api/v1/auth/account-providers', 'GET', () => jsonResponse({ items: providers }))
}

describe('OAuthIdentitiesPage (linked-accounts #706)', () => {
  it('renders linked accounts of both kinds and extensions without executing unknown fields', async () => {
    seedRoutes()
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByRole('heading', { name: '已连接账号' })).toBeTruthy()
    expect(screen.getByText('GitHub')).toBeTruthy()
    expect(screen.getByText('octocat@example.com')).toBeTruthy()
    expect(screen.getByText('CLtermux 用户')).toBeTruthy()
    expect(screen.getByText('cltermux:sub-001')).toBeTruthy()
    expect(screen.getByText('OAuth 身份')).toBeTruthy()
    expect(screen.getByText('服务账号')).toBeTruthy()
    expect(screen.getAllByText('42 天')).toBeTruthy()
    expect(screen.getByText('该字段类型暂不支持展示')).toBeTruthy()
    expect(screen.queryByText('<script>')).toBeNull()
    expect(screen.queryByText('gh-subject-42')).toBeNull()
    expect(screen.getByText(/gh.*••••.*42/)).toBeTruthy()
  })

  it('shows empty state with a binding entry when nothing is linked and no provider exists', async () => {
    seedRoutes({ accounts: [], providers: [] })
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByText('暂无已连接账号')).toBeTruthy()
    expect(screen.getByRole('link', { name: '前往账户绑定' }).getAttribute('href')).toBe('/console/profile')
  })

  it('shows a bind entry when an account provider is available', async () => {
    seedRoutes({ accounts: [], providers: [PROVIDER] })
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByRole('heading', { name: '绑定 CLtermux' })).toBeTruthy()
  })

  it('binds a service account and prepends the fresh snapshot', async () => {
    setCsrfCookie()
    seedRoutes({ accounts: [] })
    const bound = { ...SERVICE_ACCOUNT, id: 'linked_new' }
    register('/api/v1/auth/account-providers/cltermux/bindings', 'POST', () => jsonResponse(bound, 201))
    render(<OAuthIdentitiesPage />)
    await screen.findAllByText('绑定 CLtermux')

    fireEvent.click(screen.getByRole('button', { name: '绑定 CLtermux' }))
    const dialog = await screen.findByRole('dialog')
    const publicInput = dialog.querySelector('#bind-public-key') as HTMLInputElement
    const privateInput = dialog.querySelector('#bind-private-key') as HTMLInputElement
    fireEvent.change(publicInput, { target: { value: 'pk-test' } })
    fireEvent.change(privateInput, { target: { value: 'sk-test' } })
    fireEvent.click(screen.getAllByRole('button', { name: /绑定 CLtermux$/ })[1])

    await waitFor(() => expect(screen.getByText('CLtermux 绑定成功。')).toBeTruthy())
    expect(screen.getByText('CLtermux 用户')).toBeTruthy()
    const bindCall = calls.find((call) => call.method === 'POST' && call.path.includes('/account-providers/cltermux/bindings'))
    expect(bindCall?.init?.headers instanceof Headers ? (bindCall.init.headers as Headers).get('X-CSRF-Token') : null).toBe('test-csrf-token')
  })

  it('rejects a refresh for service accounts and keeps the stale snapshot when it fails', async () => {
    seedRoutes()
    let refreshCalls = 0
    register('/api/v1/auth/linked-accounts/linked_cltermux_1/refresh', 'POST', () => {
      refreshCalls += 1
      return refreshCalls === 1
        ? jsonResponse({ ...SERVICE_ACCOUNT, sync: { ...SERVICE_ACCOUNT.sync, status: 'failed', error: 'network down' } })
        : jsonResponse({ ...SERVICE_ACCOUNT, sync: { ...SERVICE_ACCOUNT.sync, status: 'success' } })
    })
    render(<OAuthIdentitiesPage />)
    await screen.findByText('CLtermux 用户')

    fireEvent.click(screen.getByRole('button', { name: '刷新 CLtermux 数据' }))
    await waitFor(() => expect(screen.getByText(/保留上一次成功快照/)).toBeTruthy())
    expect(screen.getAllByText('42 天')).toBeTruthy()
    expect(screen.getByText('同步失败')).toBeTruthy()
  })

  it('updates the snapshot after a successful refresh click', async () => {
    seedRoutes()
    register('/api/v1/auth/linked-accounts/linked_cltermux_1/refresh', 'POST', () => jsonResponse({
      ...SERVICE_ACCOUNT,
      sync: { ...SERVICE_ACCOUNT.sync, status: 'success', last_success_at: '2026-09-06T08:00:00Z' },
    }))
    render(<OAuthIdentitiesPage />)
    await screen.findByText('CLtermux 用户')

    fireEvent.click(screen.getByRole('button', { name: '刷新 CLtermux 数据' }))
    await waitFor(() => expect(screen.getByText('CLtermux 数据已刷新。')).toBeTruthy())
  })

  it('unlinks a service account after password reconfirmation', async () => {
    setCsrfCookie()
    seedRoutes()
    register('/api/v1/auth/linked-accounts/linked_cltermux_1', 'DELETE', () => emptyResponse(204))
    render(<OAuthIdentitiesPage />)
    await screen.findByText('CLtermux 用户')

    fireEvent.click(screen.getByRole('button', { name: '解除 CLtermux 绑定' }))
    const dialog = await screen.findByRole('dialog')
    const password = dialog.querySelector('#unlink-account-password') as HTMLInputElement
    fireEvent.change(password, { target: { value: 'secret' } })
    fireEvent.click(screen.getByRole('button', { name: '确认解除绑定' }))

    await waitFor(() => expect(screen.queryByText('CLtermux 用户')).toBeNull())
    expect(screen.getByText('CLtermux 已解除绑定。')).toBeTruthy()
    const deleteCall = calls.find((call) => call.method === 'DELETE')
    expect(deleteCall?.path).toBe('/api/v1/auth/linked-accounts/linked_cltermux_1')
  })

  it('rejects malformed typed extension values through the response guard', async () => {
    seedRoutes({
      accounts: [{ ...SERVICE_ACCOUNT, extensions: [{ ...SERVICE_ACCOUNT.extensions[0], fields: [{ key: 'remaining_days', label: '剩余订阅', type: 'duration_days', value: '42' }] }] }],
      providers: [],
    })
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByText(/无法加载已连接账号/)).toBeTruthy()
    expect(screen.queryByText('CLtermux 用户')).toBeNull()
  })

  it('paginates with next_cursor and appends further rows', async () => {
    seedRoutes({
      accounts: [OAUTH_ACCOUNT],
      nextCursor: 'cursor-1',
      providers: [],
    })
    register('/api/v1/auth/linked-accounts', 'GET', (init) => {
      const url = (init?.body as string | undefined) ?? ''
      return jsonResponse({ items: [OAUTH_ACCOUNT], next_cursor: url.includes('cursor-1') ? null : 'cursor-1' })
    })
    render(<OAuthIdentitiesPage />)
    await screen.findByText('GitHub')

    fireEvent.click(screen.getByRole('button', { name: '加载更多' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '加载更多' })).toBeTruthy())
    const cursorCall = calls.find((call) => call.path.includes('cursor=cursor-1'))
    expect(cursorCall).toBeTruthy()
  })

  it('hides the load-more control when no next_cursor is returned', async () => {
    seedRoutes({ nextCursor: null, providers: [] })
    render(<OAuthIdentitiesPage />)
    await screen.findByText('GitHub')
    expect(screen.queryByRole('button', { name: '加载更多' })).toBeNull()
  })

  it('provides an accessible full-value control for long extension values', async () => {
    const longValue = 'device-' + 'x'.repeat(140)
    seedRoutes({
      accounts: [{ ...SERVICE_ACCOUNT, extensions: [{ ...SERVICE_ACCOUNT.extensions[0], fields: [{ key: 'device', label: '设备状态', type: 'text', value: longValue }] }] }],
      providers: [],
    })
    render(<OAuthIdentitiesPage />)

    await screen.findByText('设备状态')
    const button = screen.getByRole('button', { name: '查看完整值' })
    expect(button.getAttribute('aria-controls')).toBeTruthy()
    expect(button.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(button)
    expect(button.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByText(`完整值：${longValue}`)).toBeTruthy()
  })
})
