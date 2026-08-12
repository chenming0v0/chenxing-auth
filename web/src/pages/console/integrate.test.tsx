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
  it.each([
    ['http://localhost:8080/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['http://example.com/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['ftp://example.com/callback', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['javascript:alert(1)', /仅允许 HTTPS，或 HTTP 回环地址/],
    ['not a url', /不是合法的 URL/],
  ] as const)('rejects %s without submitting', async (uri: string, reason: RegExp) => {
    render(<IntegratePage />)
    fireEvent.click(screen.getAllByRole('button', { name: '注册新应用' })[0])
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '本地调试应用' } })
    fireEvent.change(screen.getByLabelText('Redirect URI'), { target: { value: uri } })
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

    const message = await screen.findByText(reason)
    expect(message.textContent).toContain('127.0.0.1')
    expect(message.textContent).toContain('[::1]')
    expect(apiFetchMock.mock.calls.some(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')).toBe(false)
  })

  it('accepts HTTPS and loopback HTTP URIs', () => {
    render(<IntegratePage />)
    fireEvent.click(screen.getAllByRole('button', { name: '注册新应用' })[0])
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '本地调试应用' } })
    fireEvent.change(screen.getByLabelText('Redirect URI'), {
      target: { value: 'https://example.com/callback\nhttp://127.0.0.1:8080/cb\nhttp://[::1]:3000/cb' },
    })
    fireEvent.click(screen.getByRole('button', { name: '创建应用' }))

    expect(apiFetchMock.mock.calls.some(([path, init]) =>
      path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')).toBe(true)
  })
})
