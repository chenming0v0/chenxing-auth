import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { AuditTable } from './audit'

function jsonResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response
}

const AUDIT = {
  id: 1,
  actor_type: 'admin',
  actor_id: '1',
  action: 'login',
  resource_type: 'session',
  resource_id: 'session-1',
  created_at: '2026-08-23T00:00:00Z',
}

function queryPage(path: string): string | null {
  return new URL(path, window.location.origin).searchParams.get('page')
}

beforeEach(() => {
  window.history.replaceState({}, '', '/admin/audit')
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('AuditTable 页码收敛（#672）', () => {
  it('direct page=999 保留全部筛选条件并 replace 到最后有效页', async () => {
    window.history.replaceState({}, '', '/admin/audit?action=login&resource_type=session&page=999')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const pushState = vi.spyOn(window.history, 'pushState')
    const queries: string[] = []
    vi.stubGlobal('fetch', (path: string) => {
      queries.push(path)
      return Promise.resolve(jsonResponse(queryPage(path) === '999'
        ? { items: [], page: 999, page_size: 20, total: 21 }
        : { items: [AUDIT], page: 2, page_size: 20, total: 21 }))
    })

    render(<AuditTable />)

    expect(await screen.findByText('session-1')).toBeTruthy()
    expect(queries.map(queryPage)).toEqual(['999', '2'])
    expect(queries.every((path) => {
      const params = new URL(path, window.location.origin).searchParams
      return params.get('action') === 'login' && params.get('resource_type') === 'session'
    })).toBe(true)
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ __chenxing_history_index: expect.any(Number) }),
      '',
      '/admin/audit?action=login&resource_type=session&page=2',
    )
    expect(pushState).not.toHaveBeenCalled()
  })

  it('翻到下一页时结果集缩小，保留筛选条件并重新加载最后有效页', async () => {
    window.history.replaceState({}, '', '/admin/audit?action=login&resource_type=session&page=2')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const queries: string[] = []
    let pageTwoCalls = 0
    vi.stubGlobal('fetch', (path: string) => {
      queries.push(path)
      const requestedPage = queryPage(path)
      if (requestedPage === '3') return Promise.resolve(jsonResponse({ items: [], page: 3, page_size: 20, total: 21 }))
      pageTwoCalls += 1
      return Promise.resolve(jsonResponse({ items: [AUDIT], page: 2, page_size: 20, total: pageTwoCalls === 1 ? 41 : 21 }))
    })

    render(<AuditTable />)
    await screen.findByText('第 2 / 3 页 · 共 41 条')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))

    expect(await screen.findByText('第 2 / 2 页 · 共 21 条')).toBeTruthy()
    expect(queries.map(queryPage)).toEqual(['2', '3', '2'])
    expect(window.location.search).toBe('?action=login&resource_type=session&page=2')
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ __chenxing_history_index: expect.any(Number) }),
      '',
      '/admin/audit?action=login&resource_type=session&page=2',
    )
    expect(screen.getByText('session-1')).toBeTruthy()
  })
})
