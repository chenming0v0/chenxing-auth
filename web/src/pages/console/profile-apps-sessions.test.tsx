import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import { ConsoleProfile } from './profile-apps'
import { installCsrfCookie } from '../../test/csrf-cookie'

const auth = vi.hoisted(() => ({ clear: vi.fn(), refresh: vi.fn(), navigate: vi.fn() }))
const USER = {
  id: 1, username: 'chenxing', email: 'user@example.test', display_name: '辰星用户', status: 'active', role: 'user',
  current_session_expires_at: '2099-01-01T00:00:00Z', avatar_updated_at: null,
}

vi.mock('../../auth-state', () => ({ useAuth: () => ({ user: USER, clear: auth.clear, refresh: auth.refresh }) }))
vi.mock('../../router', () => ({ useNavigate: () => auth.navigate }))
vi.mock('../../components/shells', () => ({ ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</> }))
vi.mock('./security', () => ({ AccountManagement: () => null }))
vi.mock('./profile-avatar', () => ({ ProfileAvatar: () => null }))

installCsrfCookie()

const ROOT = '/api/v1/auth/sessions'
const CURRENT = { id: 1, current: true, created_at: '2026-01-01T00:00:00Z', expires_at: '2099-01-01T00:00:00Z' }
const OTHER = { ...CURRENT, id: 2, current: false }
const THIRD = { ...OTHER, id: 3 }
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

function installNetwork(onList: () => Response | Promise<Response>, onDelete: (path: string) => Response | Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({ path, method })
    if (path === ROOT && method === 'GET') return Promise.resolve(onList())
    if (path.startsWith(`${ROOT}/`) && method === 'DELETE') return Promise.resolve(onDelete(path))
    throw new Error(`unexpected request: ${path}`)
  }))
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/profile')
  calls = []
  auth.clear.mockReset()
  auth.refresh.mockReset()
  auth.navigate.mockReset()
  vi.stubGlobal('confirm', vi.fn(() => true))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('会话撤销结果立即反映在本地列表（#747）', () => {
  it.each([204, 404])('DELETE 返回 %s 后立即移除会话，后台列表失败也不恢复旧行', async (status) => {
    let listCalls = 0
    const reload = deferredResponse()
    installNetwork(() => ++listCalls === 1 ? jsonResponse({ items: [OTHER, CURRENT] }) : reload.promise, () => jsonResponse(null, status))
    render(<ConsoleProfile />)
    await screen.findByText('其他会话')
    fireEvent.click(screen.getAllByRole('button', { name: '撤销' })[0])

    await waitFor(() => expect(listCalls).toBe(2))
    expect(screen.queryByText('其他会话')).toBeNull()
    expect(screen.getByText('当前会话')).toBeTruthy()
    // DELETE 已完成即可继续管理其他会话，不必等待后台 GET。
    expect(screen.getByRole('button', { name: '撤销' })).toHaveProperty('disabled', false)

    await act(async () => {
      reload.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
      await reload.promise
    })

    expect(screen.queryByText('其他会话')).toBeNull()
    expect(screen.getAllByRole('button', { name: '撤销' })).toHaveLength(1)
    expect(screen.getByRole('button', { name: '撤销' })).toHaveProperty('disabled', false)
    expect(auth.clear).not.toHaveBeenCalled()
    expect(auth.navigate).not.toHaveBeenCalled()
  })

  it('两次撤销后的旧 GET 晚于新 GET 失败返回，也不能复活已撤销会话', async () => {
    let listCalls = 0
    const oldReload = deferredResponse()
    installNetwork(() => {
      listCalls += 1
      if (listCalls === 1) return jsonResponse({ items: [OTHER, THIRD] })
      if (listCalls === 2) return oldReload.promise
      return jsonResponse({ code: 'temporarily_unavailable' }, 503)
    }, () => jsonResponse(null, 204))
    render(<ConsoleProfile />)
    await screen.findAllByText('其他会话')
    fireEvent.click(screen.getAllByRole('button', { name: '撤销' })[0])
    await waitFor(() => expect(screen.getAllByRole('button', { name: '撤销' })).toHaveLength(1))
    const remaining = screen.getByRole('button', { name: '撤销' })
    expect(remaining).toHaveProperty('disabled', false)
    fireEvent.click(remaining)
    await waitFor(() => expect(listCalls).toBe(3))
    expect(screen.getByText('暂无活跃会话')).toBeTruthy()

    await act(async () => {
      oldReload.resolve(jsonResponse({ items: [THIRD] }))
      await oldReload.promise
    })

    expect(screen.queryByText('其他会话')).toBeNull()
    expect(screen.queryByRole('button', { name: '撤销' })).toBeNull()
    expect(screen.getByText('暂无活跃会话')).toBeTruthy()
    expect(calls.filter((call) => call.method === 'DELETE').map((call) => call.path)).toEqual([`${ROOT}/2`, `${ROOT}/3`])
  })

  it.each([204, 404])('当前会话 DELETE 返回 %s 时仍清理认证状态并跳回登录', async (status) => {
    let listCalls = 0
    installNetwork(() => {
      listCalls += 1
      return jsonResponse({ items: [CURRENT] })
    }, () => jsonResponse(null, status))
    render(<ConsoleProfile />)
    fireEvent.click(await screen.findByRole('button', { name: '撤销' }))

    await waitFor(() => expect(auth.clear).toHaveBeenCalledTimes(1))
    expect(auth.navigate).toHaveBeenCalledWith('/login?returnTo=%2Fconsole%2Fprofile')
    expect(listCalls).toBe(1)
    expect(screen.queryByRole('button', { name: '撤销' })).toBeNull()
  })

  it('撤销失败保留会话并释放锁，第二次尝试成功后移除', async () => {
    let deleteCalls = 0
    let listCalls = 0
    installNetwork(() => jsonResponse({ items: ++listCalls === 1 ? [OTHER] : [] }), () => {
      deleteCalls += 1
      return deleteCalls === 1 ? jsonResponse({ code: 'temporarily_unavailable' }, 503) : jsonResponse(null, 204)
    })
    render(<ConsoleProfile />)
    fireEvent.click(await screen.findByRole('button', { name: '撤销' }))
    await waitFor(() => expect(screen.getByRole('button', { name: '撤销' })).toHaveProperty('disabled', false))
    expect(screen.getByText('其他会话')).toBeTruthy()
    expect(listCalls).toBe(1)
    fireEvent.click(screen.getByRole('button', { name: '撤销' }))

    await waitFor(() => expect(screen.queryByRole('button', { name: '撤销' })).toBeNull())
    expect(deleteCalls).toBe(2)
    expect(screen.getByText('暂无活跃会话')).toBeTruthy()
  })

  it('同一渲染周期的重复撤销只确认并发送一次 DELETE，取消后也能再次操作', async () => {
    const confirm = vi.fn().mockReturnValueOnce(false).mockReturnValue(true)
    vi.stubGlobal('confirm', confirm)
    const deletion = deferredResponse()
    let listCalls = 0
    installNetwork(() => jsonResponse({ items: ++listCalls === 1 ? [OTHER] : [] }), () => deletion.promise)
    render(<ConsoleProfile />)
    const revoke = await screen.findByRole('button', { name: '撤销' })
    fireEvent.click(revoke)
    expect(calls.filter((call) => call.method === 'DELETE')).toHaveLength(0)
    expect(revoke).toHaveProperty('disabled', false)

    act(() => {
      revoke.dispatchEvent(new MouseEvent('click', { bubbles: true }))
      revoke.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    })

    expect(confirm).toHaveBeenCalledTimes(2)
    expect(calls.filter((call) => call.method === 'DELETE')).toHaveLength(1)
    expect(revoke).toHaveProperty('disabled', true)
    await act(async () => {
      deletion.resolve(jsonResponse(null, 204))
      await deletion.promise
    })
    expect(screen.queryByRole('button', { name: '撤销' })).toBeNull()
  })
})
