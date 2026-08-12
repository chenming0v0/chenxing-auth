import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { IntegratePage } from './integrate'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => new Promise(() => {})),
}))

vi.mock('../../api', () => ({
  apiFetch: apiFetchMock,
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./shared', () => ({
  entitlementState: () => ({
    kind: 'ready',
    plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' },
    data: { plan: { code: 'basic', name: '基础版', description: null, validity: 'permanent' }, entitlements: [] },
  }),
  SelfServiceClosedBlock: ({ children }: { children: ReactNode }) => <>{children}</>,
  useEntitlements: () => ({ data: null, error: '', loading: false, retry: vi.fn() }),
}))

beforeEach(() => { apiFetchMock.mockClear() })
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const CLIENT = {
  id: 1,
  client_id: 'cx-client-demo',
  client_name: '演示应用',
  redirect_uris: ['https://app.example.com/callback'],
  scopes: ['openid'],
  status: 'active' as const,
  quota: { daily_limit: null, daily_used: 0, monthly_limit: null, monthly_used: 0 },
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

describe('IntegratePage documentation link', () => {
  it('uses the published API wiki instead of a placeholder href', () => {
    render(<IntegratePage />)

    const link = screen.getByRole('link', { name: '接入文档' })
    expect(link.getAttribute('href')).toBe('https://wiki.auth.clya.top')
    expect(link.getAttribute('href')).not.toBe('#')
  })
})

describe('IntegratePage Redirect URI guidance', () => {
  it('explains the loopback IP requirement before submitting an HTTP localhost URI', async () => {
    render(<IntegratePage />)
    fireEvent.click(screen.getAllByRole('button', { name: '注册新应用' })[0])
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '本地调试应用' } })
    fireEvent.change(screen.getByLabelText('Redirect URI'), {
      target: { value: 'http://localhost:8080/callback' },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

    const message = await screen.findByText(/localhost 不能作为 HTTP Redirect URI/)
    expect(message.textContent).toContain('127.0.0.1')
    expect(message.textContent).toContain('[::1]')
    expect(apiFetchMock.mock.calls.some(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')).toBe(false)
  })
})
