import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, render, screen, waitFor, fireEvent, within } from '@testing-library/react'
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

const REVOKE_BODY = '撤销后，该应用将无法再通过辰星通行证获取你的账户信息或保持登录，需要重新授权才能继续使用辰星通行证登录。'
const REVOKE_NOTICE = '此操作仅撤销辰星通行证对该应用的授权，不会删除或解绑你在该应用中的账号、数据或设备。已签发的访问凭证可能在短时间内仍然有效。如需彻底解除绑定，请在该应用内操作或联系应用管理员。'

/** 列表 GET 按调用顺序返回给定的 deferred，用来构造 B/C 先返回、A 后返回。 */
function stubListLoads(pending: Array<Deferred<Response>>, deleteResponse?: Response | Promise<Response>) {
  let index = 0
  requests = []
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
      return Promise.resolve(deleteResponse ?? { ok: true, status: 204, json: async () => undefined } as Response)
    }
    return Promise.reject(new Error(`unexpected request: ${method} ${url}`))
  }))
}

function openRevokeDialog() {
  fireEvent.click(screen.getByRole('button', { name: '撤销授权' }))
  return screen.getByRole('dialog', { name: '撤销对“新响应应用”的授权？' })
}

function confirmRevokeDialog() {
  fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: '撤销授权' }))
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

    openRevokeDialog()
    confirmRevokeDialog()
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

describe('AuthorizedApps 撤销确认', () => {
  async function renderOneApp(deleteResponse?: Response | Promise<Response>) {
    const request = deferred<Response>()
    stubListLoads([request], deleteResponse)
    render(<AuthorizedApps />)
    await act(async () => {
      request.resolve(jsonResponse({ items: [NEW_APP] }))
      await request.promise
    })
    expect(await screen.findByText('新响应应用')).toBeTruthy()
  }

  it('打开确认框展示说明；取消、关闭、Escape 和遮罩都不发 DELETE，确认才撤销', async () => {
    const confirm = vi.spyOn(window, 'confirm')
    await renderOneApp()

    const dialog = openRevokeDialog()
    expect(dialog.parentElement?.className).toContain('chenxing-modal-overlay')
    expect(screen.getByText(REVOKE_BODY)).toBeTruthy()
    expect(screen.getByText(REVOKE_NOTICE)).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByRole('button', { name: '取消' }))

    fireEvent.click(screen.getByRole('button', { name: '取消' }))
    expect(screen.queryByRole('dialog')).toBeNull()

    fireEvent.click(within(openRevokeDialog()).getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('dialog')).toBeNull()

    fireEvent.keyDown(openRevokeDialog(), { key: 'Escape' })
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).toBeNull()

    const overlay = openRevokeDialog().parentElement
    if (!overlay) throw new Error('revoke dialog overlay is missing')
    fireEvent.mouseDown(overlay)
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(requests.some((item) => item.method === 'DELETE')).toBe(false)
    expect(screen.getByText('新响应应用')).toBeTruthy()

    openRevokeDialog()
    confirmRevokeDialog()
    expect(await screen.findByText('应用授权已撤销。')).toBeTruthy()
    expect(requests).toContainEqual({ path: `${APPS_PATH}/cid-new`, method: 'DELETE' })
    expect(confirm).not.toHaveBeenCalled()
    confirm.mockRestore()
  })

  it('撤销请求未结束前不能关闭确认框', async () => {
    const deletion = deferred<Response>()
    await renderOneApp(deletion.promise)
    openRevokeDialog()
    confirmRevokeDialog()

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByRole('button', { name: '撤销中…' })).toHaveProperty('disabled', true)
    expect(within(dialog).getByRole('button', { name: '取消' })).toHaveProperty('disabled', true)
    fireEvent.click(within(dialog).getByRole('button', { name: '取消' }))
    fireEvent.click(within(dialog).getByRole('button', { name: '关闭' }))
    fireEvent.keyDown(document, { key: 'Escape' })
    const overlay = dialog.parentElement
    if (!overlay) throw new Error('revoke dialog overlay is missing')
    fireEvent.mouseDown(overlay)
    expect(screen.getByRole('dialog')).toBe(dialog)
    expect(requests.filter((item) => item.method === 'DELETE')).toHaveLength(1)

    await act(async () => {
      deletion.resolve({ ok: true, status: 204, json: async () => undefined } as Response)
      await deletion.promise
    })
    expect(await screen.findByText('应用授权已撤销。')).toBeTruthy()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('撤销失败时保留应用，并沿用页面上的失败提示', async () => {
    await renderOneApp(jsonResponse({ code: 'internal' }, 500))
    openRevokeDialog()
    confirmRevokeDialog()
    expect(await screen.findByText('服务暂时不可用，请稍后重试。')).toBeTruthy()
    expect(screen.queryByText('应用授权已撤销。')).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
    expect(screen.getByText('新响应应用')).toBeTruthy()
  })
})
