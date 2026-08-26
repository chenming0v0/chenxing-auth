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

const PLAN_BASIC = {
  id: 1,
  code: 'basic',
  name: '基础版',
  description: null,
  oauth_clients_limit: 2,
  daily_auth_limit: 2500,
  monthly_auth_limit: 50000,
  max_qps: 10,
  price_points: 0,
  billing_period: 'one_time',
  is_default: true,
  status: 'active' as const,
  assigned_users: 0,
}

const PLAN_PRO = {
  id: 2,
  code: 'pro',
  name: '专业版',
  description: null,
  oauth_clients_limit: 10,
  daily_auth_limit: 10000,
  monthly_auth_limit: 200000,
  max_qps: 20,
  price_points: 40,
  billing_period: 'monthly',
  is_default: false,
  status: 'active' as const,
  assigned_users: 0,
}

const PLAN_TEAM = {
  ...PLAN_PRO,
  id: 3,
  code: 'team',
  name: '团队版',
}

describe('AdminPlans', () => {
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
    const posted = fetchMock.mock.calls.find(([path, init]) => path === '/api/v1/admin/plans' && init?.method === 'POST')
    expect(JSON.parse(String(posted?.[1]?.body))).toEqual(expect.objectContaining({
      price_points: 0,
      billing_period: 'one_time',
    }))
    release()
    await pending
  })

  it('新建套餐表单默认售价 0，并展示计费周期', async () => {
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (path === '/api/v1/admin/plans' && method === 'GET') return Promise.resolve(jsonResponse([]))
      return Promise.reject(new Error(`unexpected ${method} ${path}`))
    })
    vi.stubGlobal('fetch', fetchMock)

    render(<AdminPlans />)
    await screen.findByRole('button', { name: '新建套餐' })
    fireEvent.click(screen.getByRole('button', { name: '新建套餐' }))

    expect((screen.getByLabelText('售价（辰星点）') as HTMLInputElement).value).toBe('0')
    expect(screen.getByRole('combobox', { name: '计费周期' }).textContent).toContain('一次性')
  })

  it('不同套餐行可并发变更，逆序 reload 响应只接受最新刷新（#682）', async () => {
    const reloadResponses: Array<{
      resolve: (value: Response) => void
      reject: (reason: Error) => void
    }> = []
    let statusChanges = 0
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (path === '/api/v1/admin/plans' && method === 'GET') {
        return new Promise<Response>((resolve, reject) => reloadResponses.push({ resolve, reject }))
      }
      if (/^\/api\/v1\/admin\/plans\/[123]\/archive$/.test(path) && method === 'POST') {
        statusChanges += 1
        return Promise.resolve(jsonResponse(null, 204))
      }
      return Promise.reject(new Error(`unexpected ${method} ${path}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('confirm', () => true)

    render(<AdminPlans />)
    await waitFor(() => expect(reloadResponses).toHaveLength(1))
    reloadResponses.shift()?.resolve(jsonResponse([PLAN_BASIC, PLAN_PRO, PLAN_TEAM]))
    await screen.findByText('基础版')

    const archiveButtons = screen.getAllByRole('button', { name: '归档' })
    archiveButtons.forEach((button) => fireEvent.click(button))

    await waitFor(() => expect(statusChanges).toBe(3))
    await waitFor(() => expect(reloadResponses).toHaveLength(3))

    const freshPlans = [
      { ...PLAN_BASIC, status: 'archived' as const },
      { ...PLAN_PRO, status: 'archived' as const },
      { ...PLAN_TEAM, status: 'archived' as const },
    ]
    reloadResponses[2]?.resolve(jsonResponse(freshPlans))
    await waitFor(() => expect(screen.getAllByRole('button', { name: '恢复' })).toHaveLength(3))
    reloadResponses[0]?.resolve(jsonResponse([PLAN_BASIC, PLAN_PRO, PLAN_TEAM]))
    reloadResponses[1]?.reject(new Error('stale reload failed'))
    await waitFor(() => {
      const restoreButtons = screen.getAllByRole('button', { name: '恢复' }) as HTMLButtonElement[]
      expect(restoreButtons.every((button) => !button.disabled)).toBe(true)
    })
    expect(screen.queryByRole('button', { name: '归档' })).toBeNull()
    expect(screen.queryByText('stale reload failed')).toBeNull()
  })
})
