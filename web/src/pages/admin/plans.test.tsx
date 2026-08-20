import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { AdminPlans } from './plans'
import { installCsrfCookie } from '../../test/csrf-cookie'

installCsrfCookie()

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./shared')>()
  return {
    ...actual,
    useAdminAccess: () => ({
      data: { user_id: 1, username: 'owner', role: 'owner', permissions: ['manage_settings'], status: 'active' },
      loading: false,
      error: '',
    }),
  }
})

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

describe('AdminPlans 套餐编辑提交互斥（#586）', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/admin/plans')
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('busy 尚未重渲染时重复提交只发出一个创建请求', async () => {
    let release = () => {}
    const pending = new Promise<Response>((resolve) => { release = () => resolve(jsonResponse({ id: 1 }, 201)) })
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (path === '/api/v1/admin/plans' && method === 'GET') return Promise.resolve(jsonResponse([]))
      if (path === '/api/v1/admin/plans' && method === 'POST') return pending
      return Promise.reject(new Error(`unexpected ${method} ${path}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<AdminPlans />)
    await screen.findByRole('button', { name: '新建套餐' })
    fireEvent.click(screen.getByRole('button', { name: '新建套餐' }))

    fireEvent.change(screen.getByLabelText('套餐代码'), { target: { value: 'pro' } })
    fireEvent.change(screen.getByLabelText('套餐名称'), { target: { value: '专业版' } })

    const form = screen.getByRole('button', { name: '创建套餐' }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => {
      expect(fetchMock.mock.calls.filter(([path, init]) => path === '/api/v1/admin/plans' && init?.method === 'POST')).toHaveLength(1)
    })
    expect(fetchMock.mock.calls.filter(([path, init]) => path === '/api/v1/admin/plans' && init?.method === 'POST')).toHaveLength(1)
    release()
    await pending
  })
})
