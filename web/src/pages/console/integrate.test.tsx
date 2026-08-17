import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import type { OwnedOAuthClient } from '../../api'
import { IntegratePage } from './integrate'

type OwnedOAuthClientList = { items: OwnedOAuthClient[]; total?: number }

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => new Promise(() => {})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./shared')>()),
  entitlementState: () => ({
    kind: 'ready',
    plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' },
    data: { plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' }, entitlements: [] },
  }),
  SelfServiceClosedBlock: ({ children }: { children: ReactNode }) => <>{children}</>,
  useEntitlements: () => ({ data: null, error: '', loading: false, retry: vi.fn() }),
}))

beforeEach(() => {
  apiFetchMock.mockReset()
  apiFetchMock.mockImplementation(() => new Promise(() => {}))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const CLIENT: OwnedOAuthClient = {
  id: 1,
  client_id: 'cx-client-demo',
  client_name: '演示应用',
  redirect_uris: ['https://app.example.com/callback'],
  scopes: ['openid'],
  status: 'active' as const,
  quota: { daily_limit: null, daily_used: 0, monthly_limit: null, monthly_used: 0 },
}

const OLD_CLIENT: OwnedOAuthClient = {
  ...CLIENT,
  id: 2,
  client_id: 'cx-client-old-response',
  client_name: '旧响应应用',
}

const NEW_CLIENT: OwnedOAuthClient = {
  ...CLIENT,
  id: 3,
  client_id: 'cx-client-new-response',
  client_name: '新响应应用',
}

type Deferred<T> = {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason?: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function mockConcurrentListLoads(first: Deferred<OwnedOAuthClientList>, second: Deferred<OwnedOAuthClientList>) {
  let listRequestIndex = 0
  apiFetchMock.mockImplementation((path, init) => {
    if (path === '/api/v1/auth/oauth-clients' && init === undefined) {
      const request = [first, second][listRequestIndex]
      listRequestIndex += 1
      return request?.promise ?? new Promise(() => {})
    }
    if (path === '/api/v1/auth/oauth-clients' && init?.method === 'POST') {
      return Promise.resolve({ ...NEW_CLIENT, client_secret: 'new-secret' })
    }
    return Promise.resolve(undefined)
  })
}

async function startSecondListLoad() {
  fireEvent.click(screen.getByRole('button', { name: '注册新应用' }))
  fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '触发刷新应用' } })
  fireEvent.change(screen.getByLabelText('Redirect URI'), { target: { value: 'https://example.com/callback' } })
  fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

  await waitFor(() => {
    const listCalls = apiFetchMock.mock.calls.filter(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init === undefined)
    expect(listCalls).toHaveLength(2)
  })
}

describe('IntegratePage 加载期间不闪空态（Issue #371）', () => {
  it('fetch 未完成时显示加载占位，不渲染「暂无 OAuth 项目」', () => {
    apiFetchMock.mockImplementation(() => new Promise(() => {}))
    render(<IntegratePage />)
    expect(screen.getByText('正在加载接入应用。')).toBeTruthy()
    expect(screen.queryByText('暂无 OAuth 项目')).toBeNull()
    expect(screen.getByText('加载中')).toBeTruthy()
  })

  it('确认没有应用后才展示空态', async () => {
    apiFetchMock.mockResolvedValue({ items: [] })
    render(<IntegratePage />)
    expect(await screen.findByText('暂无 OAuth 项目')).toBeTruthy()
    expect(screen.queryByText('正在加载接入应用。')).toBeNull()
  })

  it('刷新列表时保留已有应用，不退回空态', async () => {
    apiFetchMock
      .mockResolvedValueOnce({ items: [CLIENT] })
      .mockResolvedValueOnce(undefined)
      .mockImplementationOnce(() => new Promise(() => {}))
    vi.stubGlobal('confirm', () => true)
    render(<IntegratePage />)
    expect(await screen.findByText('演示应用')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '禁用' }))

    await waitFor(() => {
      expect(apiFetchMock.mock.calls.some(([path, init]) =>
        typeof path === 'string' && path.endsWith('/disable') && init?.method === 'POST')).toBe(true)
    })
    await waitFor(() => expect(apiFetchMock.mock.calls.filter(([path]) =>
      path === '/api/v1/auth/oauth-clients').length).toBe(2))
    expect(screen.getByText('演示应用')).toBeTruthy()
    expect(screen.queryByText('暂无 OAuth 项目')).toBeNull()
    expect(screen.queryByText('正在加载接入应用。')).toBeNull()
  })
})

describe('IntegratePage 并发列表加载（Issue #486）', () => {
  it('B 先返回、A 后返回时最终保留较新的 B 响应', async () => {
    const requestA = deferred<OwnedOAuthClientList>()
    const requestB = deferred<OwnedOAuthClientList>()
    mockConcurrentListLoads(requestA, requestB)
    render(<IntegratePage />)
    await startSecondListLoad()

    await act(async () => {
      requestB.resolve({ items: [NEW_CLIENT], total: 1 })
      await requestB.promise
    })
    expect(screen.getByText('新响应应用')).toBeTruthy()
    expect(screen.getByText('1 个应用')).toBeTruthy()

    await act(async () => {
      requestA.resolve({ items: [OLD_CLIENT], total: 1 })
      await requestA.promise
    })
    expect(screen.getByText('新响应应用')).toBeTruthy()
    expect(screen.queryByText('旧响应应用')).toBeNull()
    expect(screen.getByText('1 个应用')).toBeTruthy()
  })

  it('旧请求失败时不能写入 message 或提前结束新请求 loading', async () => {
    const requestA = deferred<OwnedOAuthClientList>()
    const requestB = deferred<OwnedOAuthClientList>()
    mockConcurrentListLoads(requestA, requestB)
    render(<IntegratePage />)
    await startSecondListLoad()

    await act(async () => {
      requestA.reject(new Error('旧请求失败'))
      await requestA.promise.catch(() => undefined)
    })
    expect(screen.queryByText('旧请求失败')).toBeNull()
    expect(screen.getByText('加载中')).toBeTruthy()
    expect(screen.getByText('正在加载接入应用。')).toBeTruthy()

    await act(async () => {
      requestB.resolve({ items: [NEW_CLIENT], total: 1 })
      await requestB.promise
    })
    expect(screen.getByText('新响应应用')).toBeTruthy()
    expect(screen.queryByText('加载中')).toBeNull()
  })
})

describe('IntegratePage documentation link', () => {
  it('uses the published API wiki instead of a placeholder href', () => {
    render(<IntegratePage />)

    const link = screen.getByRole('link', { name: '接入文档' })
    expect(link.getAttribute('href')).toBe('https://wiki.auth.clya.top')
    expect(link.getAttribute('href')).not.toBe('#')
  })
})

describe('IntegratePage Redirect URI guidance', () => {
  it.each([
    ['http://localhost:8080/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['http://example.com/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['ftp://example.com/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['javascript:alert(1)', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['not a url', /不是合法的 URL/],
  ] as const)('rejects %s without submitting', async (uri: string, reason: RegExp) => {
    render(<IntegratePage />)
    fireEvent.click(screen.getAllByRole('button', { name: '注册新应用' })[0])
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '本地调试应用' } })
    fireEvent.change(screen.getByLabelText('Redirect URI'), { target: { value: uri } })
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

    const message = await screen.findByText(reason)
    expect(message.textContent).toContain('127.0.0.1')
    expect(message.textContent).toContain('[::1]')
    expect(apiFetchMock.mock.calls.some(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')).toBe(false)
  })

  it('accepts HTTPS and loopback HTTP URIs', () => {
    render(<IntegratePage />)
    fireEvent.click(screen.getAllByRole('button', { name: '注册新应用' })[0])
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '本地调试应用' } })
    fireEvent.change(screen.getByLabelText('Redirect URI'), {
      target: { value: 'https://example.com/callback\nhttp://127.0.0.1:8080/cb\nhttp://[::1]:3000/cb' },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

    const createCall = apiFetchMock.mock.calls.find(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')
    expect(createCall).toBeTruthy()
    expect(createCall?.[1]?.headers).toEqual({ 'Idempotency-Key': expect.any(String) })
  })

  it('reuses a retry key for Secret rotation', async () => {
    apiFetchMock.mockResolvedValue({ items: [CLIENT] })
    vi.stubGlobal('confirm', () => true)
    render(<IntegratePage />)
    expect(await screen.findByText('演示应用')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '轮换' }))

    await waitFor(() => {
      const rotateCall = apiFetchMock.mock.calls.find(([path, init]) =>
        typeof path === 'string' && path.endsWith('/rotate-secret') && init?.method === 'POST')
      expect(rotateCall?.[1]?.headers).toEqual({ 'Idempotency-Key': expect.any(String) })
    })
  })
})
