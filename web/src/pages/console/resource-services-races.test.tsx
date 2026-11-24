import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { ResourceServicesPage } from './resource-services'
import { installCsrfCookie } from '../../test/csrf-cookie'

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

installCsrfCookie()

const ROOT = '/api/v1/auth/resource-services'
const PROVIDER = {
  id: '11111111-1111-4111-8111-111111111111', slug: 'demo', display_name: '示例资源服务',
  issuer: 'https://provider.example.test', identifier_label: '账号', secret_label: '密码', identifier_sensitive: false,
}
const BINDING = {
  id: '22222222-2222-4222-8222-222222222222', provider_id: PROVIDER.id, issuer: PROVIDER.issuer,
  uid: 'acct-1001', account: 'demo-account', name: '原来的账号', status: 'active',
  snapshot: { schema_version: '1', issuer: PROVIDER.issuer, uid: 'acct-1001', account: 'demo-account', name: '原来的账号', status: 'active', fields: [] },
  grant_expires_at: '2099-01-01T00:00:00Z', access_expires_at: '2099-01-01T00:00:00Z', refresh_expires_at: '2099-01-01T00:00:00Z',
}
const UPDATED = { ...BINDING, name: '更新后的账号', snapshot: { ...BINDING.snapshot, name: '更新后的账号' } }
type Action = 'sync' | 'refresh' | 'unlink'
type Call = { path: string; method: string }
let calls: Call[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

function installNetwork(onList: () => Response | Promise<Response>, onMutation: (path: string, method: string) => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ path, method })
    if (path === ROOT && method === 'GET') return Promise.resolve(jsonResponse([PROVIDER]))
    if (path === `${ROOT}/bindings` && method === 'GET') return Promise.resolve(onList())
    return Promise.resolve(onMutation(path, method))
  }))
}

function actionButton(action: Action): HTMLElement {
  if (action !== 'unlink') return screen.getByRole('button', { name: action === 'sync' ? '同步' : '刷新令牌' })
  fireEvent.click(screen.getByRole('button', { name: '解除账号关联' }))
  return within(screen.getByRole('dialog')).getByRole('button', { name: '解除账号关联' })
}

function mutationResponse(action: Action): Response {
  return action === 'unlink' ? jsonResponse(null, 204) : jsonResponse(UPDATED)
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/account/resource-services')
  calls = []
  vi.stubGlobal('crypto', { randomUUID: () => '33333333-3333-4333-8333-333333333333' })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('列表错误态与资源服务变更隔离（#746）', () => {
  it.each(['sync', 'refresh', 'unlink'] as const)('%s 期间同一事件内的重试不能发 GET，旧 GET 也不能覆盖成功结果', async (action) => {
    let listCalls = 0
    const oldList = deferredResponse()
    const mutation = deferredResponse()
    installNetwork(() => {
      listCalls += 1
      if (listCalls === 1) return jsonResponse([BINDING])
      if (listCalls === 2) return jsonResponse({ code: 'temporarily_unavailable' }, 503)
      if (listCalls === 3) return oldList.promise
      return jsonResponse(action === 'unlink' ? [] : [UPDATED])
    }, () => mutation.promise)
    render(<ResourceServicesPage />)
    expect(await screen.findByText('原来的账号')).toBeTruthy()
    const refresh = screen.getByRole('button', { name: '刷新' })
    fireEvent.click(refresh)
    const retry = await screen.findByRole('button', { name: '重试' })

    // 先挂起一个旧快照请求，再在变更开始的同一渲染周期尝试第二次重试。
    fireEvent.click(retry)
    await waitFor(() => expect(listCalls).toBe(3))
    const submit = actionButton(action)
    act(() => {
      submit.dispatchEvent(new MouseEvent('click', { bubbles: true }))
      retry.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(listCalls).toBe(3)
    expect(retry).toHaveProperty('disabled', true)
    expect(refresh).toHaveProperty('disabled', true)
    expect(calls.filter((call) => call.method !== 'GET')).toEqual([{
      path: `${ROOT}/bindings/${BINDING.id}${action === 'unlink' ? '' : `/${action}`}`,
      method: action === 'unlink' ? 'DELETE' : 'POST',
    }])

    await act(async () => {
      mutation.resolve(mutationResponse(action))
      await mutation.promise
    })
    if (action === 'unlink') expect(screen.queryByText('demo-account')).toBeNull()
    else expect(screen.getByText('更新后的账号')).toBeTruthy()

    await act(async () => {
      oldList.resolve(jsonResponse([BINDING]))
      await oldList.promise
    })

    expect(screen.queryByText('原来的账号')).toBeNull()
    if (action === 'unlink') expect(screen.queryByText('demo-account')).toBeNull()
    else expect(screen.getByText('更新后的账号')).toBeTruthy()
    expect(retry).toHaveProperty('disabled', false)
    fireEvent.click(retry)
    await waitFor(() => expect(screen.queryByRole('button', { name: '重试' })).toBeNull())
    expect(listCalls).toBe(4)
  })

  it.each(['sync', 'refresh', 'unlink'] as const)('%s 失败会释放重试入口并保留原绑定', async (action) => {
    let listCalls = 0
    const mutation = deferredResponse()
    installNetwork(() => {
      listCalls += 1
      return listCalls === 2 ? jsonResponse({ code: 'temporarily_unavailable' }, 503) : jsonResponse([BINDING])
    }, () => mutation.promise)
    render(<ResourceServicesPage />)
    expect(await screen.findByText('原来的账号')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '刷新' }))
    const retry = await screen.findByRole('button', { name: '重试' })
    fireEvent.click(actionButton(action))
    expect(retry).toHaveProperty('disabled', true)

    await act(async () => {
      mutation.resolve(jsonResponse({ code: 'provider_unavailable' }, 503))
      await mutation.promise
    })

    expect(retry).toHaveProperty('disabled', false)
    expect(screen.getByText('原来的账号')).toBeTruthy()
    if (action === 'unlink') fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '取消' }))
    fireEvent.click(retry)
    await waitFor(() => expect(screen.queryByRole('button', { name: '重试' })).toBeNull())
    expect(listCalls).toBe(3)
    expect(screen.getByRole('button', { name: action === 'sync' ? '同步' : action === 'refresh' ? '刷新令牌' : '解除账号关联' })).toHaveProperty('disabled', false)
  })

  it('绑定成功后，变更前挂起的空列表不能再次抹掉新绑定', async () => {
    let listCalls = 0
    const oldList = deferredResponse()
    const mutation = deferredResponse()
    installNetwork(() => ++listCalls === 1 ? jsonResponse([]) : oldList.promise, () => mutation.promise)
    render(<ResourceServicesPage />)
    const bind = await screen.findByRole('button', { name: '绑定' })
    fireEvent.click(screen.getByRole('button', { name: '刷新' }))
    await waitFor(() => expect(listCalls).toBe(2))
    fireEvent.click(bind)
    fireEvent.change(screen.getByLabelText('账号'), { target: { value: 'demo-account' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'secret-value' } })
    fireEvent.click(screen.getByRole('button', { name: '确认绑定' }))

    await act(async () => {
      mutation.resolve(jsonResponse(BINDING, 201))
      await mutation.promise
    })
    expect(await screen.findByText('原来的账号')).toBeTruthy()
    await act(async () => {
      oldList.resolve(jsonResponse([]))
      await oldList.promise
    })

    expect(screen.getByText('原来的账号')).toBeTruthy()
    expect(screen.getByText('demo-account')).toBeTruthy()
    expect(screen.queryByRole('button', { name: '绑定' })).toBeNull()
    expect(calls.filter((call) => call.method === 'POST')).toEqual([{ path: `${ROOT}/bindings`, method: 'POST' }])
  })
})
