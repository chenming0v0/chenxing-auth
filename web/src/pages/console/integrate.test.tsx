import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
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
afterEach(cleanup)

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
