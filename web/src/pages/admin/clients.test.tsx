import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { ClientsTable } from './clients'

function jsonResponse(body: unknown): Response {
  return { ok: true, status: 200, json: async () => body } as Response
}

const ACCESS = {
  data: { user_id: 1, username: 'owner', role: 'owner' as const, permissions: ['manage_clients'], status: 'active' },
  loading: false,
  error: '',
}

const CLIENT = {
  client_name: '辰星应用',
  redirect_uris: ['https://client.example/callback'],
  scopes: ['openid'],
  client_id: 'cx-client',
  status: 'active',
  owner_user_id: 1,
  auth_method: 'client_secret_basic',
  logo_uri: null,
  client_uri: null,
}

function queryPage(path: string): string | null {
  return new URL(path, window.location.origin).searchParams.get('page')
}

beforeEach(() => {
  window.history.replaceState({}, '', '/admin/clients')
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('ClientsTable 页码收敛（#672）', () => {
  it('direct page=999 保留搜索条件并 replace 到最后有效页', async () => {
    window.history.replaceState({}, '', '/admin/clients?search=star&page=999')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const pushState = vi.spyOn(window.history, 'pushState')
    const queries: string[] = []
    vi.stubGlobal('fetch', (path: string) => {
      queries.push(path)
      return Promise.resolve(jsonResponse(queryPage(path) === '999'
        ? { items: [], page: 999, page_size: 20, total: 21 }
        : { items: [CLIENT], page: 2, page_size: 20, total: 21 }))
    })

    render(<ClientsTable access={ACCESS} />)

    expect(await screen.findByText('辰星应用')).toBeTruthy()
    expect(queries.map(queryPage)).toEqual(['999', '2'])
    expect(queries.every((path) => new URL(path, window.location.origin).searchParams.get('search') === 'star')).toBe(true)
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ __chenxing_history_index: expect.any(Number) }),
      '',
      '/admin/clients?search=star&page=2',
    )
    expect(pushState).not.toHaveBeenCalled()
  })

  it('翻到下一页时结果集缩小，replace 回最后有效页并重新查询', async () => {
    window.history.replaceState({}, '', '/admin/clients?search=star&page=2')
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const queries: string[] = []
    let pageTwoCalls = 0
    vi.stubGlobal('fetch', (path: string) => {
      queries.push(path)
      const requestedPage = queryPage(path)
      if (requestedPage === '3') return Promise.resolve(jsonResponse({ items: [], page: 3, page_size: 20, total: 21 }))
      pageTwoCalls += 1
      return Promise.resolve(jsonResponse({ items: [CLIENT], page: 2, page_size: 20, total: pageTwoCalls === 1 ? 41 : 21 }))
    })

    render(<ClientsTable access={ACCESS} />)
    await screen.findByText('第 2 / 3 页 · 共 41 条')
    fireEvent.click(screen.getByRole('button', { name: '下一页' }))

    expect(await screen.findByText('第 2 / 2 页 · 共 21 条')).toBeTruthy()
    expect(queries.map(queryPage)).toEqual(['2', '3', '2'])
    expect(window.location.search).toBe('?search=star&page=2')
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ __chenxing_history_index: expect.any(Number) }),
      '',
      '/admin/clients?search=star&page=2',
    )
    await waitFor(() => expect(screen.getByText('辰星应用')).toBeTruthy())
  })
})
