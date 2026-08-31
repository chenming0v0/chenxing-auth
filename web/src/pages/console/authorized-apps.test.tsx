import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, fireEvent } from '@testing-library/react'
import { StrictMode, type ReactNode } from 'react'
import { AuthorizedApps } from './authorized-apps'
import { installCsrfCookie } from '../../test/csrf-cookie'

/**
 * #688：已授权应用列表的 loader 与撤销后的静默刷新共享一条 request id 序列。
 * StrictMode 会重放初始 effect，因此「先发后到」的旧快照必须被丢弃，否则已撤销的
 * 授权会重新显示为「已连接」。
 *
 * 只 stub fetch 这一层公共边界，apiFetch 与页面逻辑跑真实实现。
 */
installCsrfCookie()

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

const APPS_PATH = '/api/v1/auth/authorized-apps'

const OLD_APP = {
  client_id: 'cid-old',
  client_name: '旧响应应用',
  scopes: ['openid', 'profile'],
  updated_at: '2026-08-05T00:00:00Z',
}

const NEW_APP = {
  client_id: 'cid-new',
  client_name: '新响应应用',
  scopes: ['openid'],
  updated_at: '2026-08-06T00:00:00Z',
}

type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void }
type CapturedRequest = { path: string; method: string }

let requests: CapturedRequest[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

/** 列表 GET 按调用顺序返回给定的 deferred，用来构造 B/C 先返回、A 后返回。 */
function stubListLoads(pending: Array<Deferred<Response>>) {
  let index = 0
  requests = []
  vi.stubGlobal('confirm', vi.fn(() => true) as unknown as typeof confirm)
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    const url = String(path)
    requests.push({ path: url, method })
    if (url === APPS_PATH && method === 'GET') {
      const target = pending[index]
      index += 1
      return target ? target.promise : new Promise<Response>(() => {})
    }
    if (url.startsWith(`${APPS_PATH}/`) && method === 'DELETE') {
      return Promise.resolve({ ok: true, status: 204, json: async () => undefined } as Response)
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
  }))
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/apps')
  requests = []
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('AuthorizedApps 并发列表加载（#688）', () => {
  it('StrictMode 双请求下，后返回的旧快照不覆盖先返回的新快照', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    stubListLoads([requestA, requestB])
    render(<StrictMode><AuthorizedApps /></StrictMode>)
    await waitFor(() => expect(requests.filter((item) => item.path === APPS_PATH).length).toBe(2))

    await act(async () => {
      requestB.resolve(jsonResponse({ items: [NEW_APP] }))
      await requestB.promise
    })
    expect(await screen.findByText('新响应应用')).toBeTruthy()

    await act(async () => {
      requestA.resolve(jsonResponse({ items: [OLD_APP] }))
      await requestA.promise
    })
    expect(screen.getByText('新响应应用')).toBeTruthy()
    expect(screen.queryByText('旧响应应用')).toBeNull()
  })

  it('撤销后的静默刷新先返回时，最初的加载响应不能让已撤销应用复活', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    const requestC = deferred<Response>()
    stubListLoads([requestA, requestB, requestC])
    render(<StrictMode><AuthorizedApps /></StrictMode>)
    await waitFor(() => expect(requests.filter((item) => item.path === APPS_PATH).length).toBe(2))

    await act(async () => {
      requestB.resolve(jsonResponse({ items: [NEW_APP] }))
      await requestB.promise
    })
    expect(await screen.findByText('新响应应用')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: '撤销授权' }))
    await screen.findByText('应用授权已撤销。')
    expect(requests).toContainEqual({ path: `${APPS_PATH}/cid-new`, method: 'DELETE' })

    await act(async () => {
      requestC.resolve(jsonResponse({ items: [] }))
      await requestC.promise
    })
    expect(screen.queryByText('新响应应用')).toBeNull()

    await act(async () => {
      requestA.resolve(jsonResponse({ items: [NEW_APP] }))
      await requestA.promise
    })
    expect(screen.queryByText('新响应应用')).toBeNull()
    expect(await screen.findByText('暂无已授权应用')).toBeTruthy()
  })

  it('旧请求失败时不写入错误提示，也不提前结束新请求的加载态', async () => {
    const requestA = deferred<Response>()
    const requestB = deferred<Response>()
    stubListLoads([requestA, requestB])
    render(<StrictMode><AuthorizedApps /></StrictMode>)
    await waitFor(() => expect(requests.filter((item) => item.path === APPS_PATH).length).toBe(2))

    await act(async () => {
      requestA.resolve(jsonResponse({ code: 'internal' }, 500))
      await requestA.promise
    })
    // 旧请求失败既不能弹出错误 Notice / 重试入口，也不能让 loading 提前结束成空态。
    expect(screen.queryByRole('button', { name: '重试' })).toBeNull()
    expect(screen.queryByText('服务暂时不可用，请稍后重试。')).toBeNull()
    expect(screen.queryByText('暂无已授权应用')).toBeNull()

    await act(async () => {
      requestB.resolve(jsonResponse({ items: [NEW_APP] }))
      await requestB.promise
    })
    expect(await screen.findByText('新响应应用')).toBeTruthy()
  })
})
