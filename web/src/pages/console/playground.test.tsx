import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { PlaygroundPage } from './playground'
import type { OwnedOAuthClient } from '../../api'

const CLIENT: OwnedOAuthClient = {
  id: 1,
  client_id: 'cx-client-demo',
  client_name: '演示应用',
  redirect_uris: ['https://app.example.com/callback'],
  scopes: ['openid'],
  status: 'active',
  quota: { daily_limit: null, daily_used: 0, monthly_limit: null, monthly_used: 0 },
  auth_method: 'client_secret_basic',
  logo_uri: null,
  client_uri: null,
}

const { apiFetchMock, listAllOwnedOAuthClientsMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn(async (_path: string, _init?: RequestInit): Promise<unknown> => ({ items: [CLIENT] })),
  listAllOwnedOAuthClientsMock: vi.fn(async () => [CLIENT]),
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
  listAllOwnedOAuthClients: listAllOwnedOAuthClientsMock,
}))

beforeEach(() => {
  apiFetchMock.mockClear()
  apiFetchMock.mockResolvedValue({ items: [CLIENT] })
  listAllOwnedOAuthClientsMock.mockClear()
  listAllOwnedOAuthClientsMock.mockResolvedValue([CLIENT])
  if (!globalThis.crypto.subtle?.digest) {
    vi.stubGlobal('crypto', {
      ...globalThis.crypto,
      getRandomValues: (bytes: Uint8Array) => {
        bytes.fill(7)
        return bytes
      },
      subtle: {
        digest: async () => new Uint8Array(32).fill(9).buffer,
      },
    })
  }
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function generateAuthorizeUrl() {
  render(<PlaygroundPage />)
  await screen.findByDisplayValue('https://app.example.com/callback')
  fireEvent.click(screen.getByRole('button', { name: '生成授权 URL' }))
  await screen.findByRole('link', { name: /打开授权端点/ })
}

describe('PlaygroundPage 加载期间不闪空态（Issue #371）', () => {
  it('fetch 未完成时显示加载占位，不渲染「需要先注册一个应用」', () => {
    listAllOwnedOAuthClientsMock.mockImplementation(() => new Promise(() => {}))
    render(<PlaygroundPage />)
    expect(screen.getByText('正在加载可用于测试的应用。')).toBeTruthy()
    expect(screen.queryByText('需要先注册一个应用')).toBeNull()
    expect(screen.queryByRole('link', { name: /前往接入应用/ })).toBeNull()
  })

  it('确认没有应用后才展示空态', async () => {
    listAllOwnedOAuthClientsMock.mockResolvedValue([])
    render(<PlaygroundPage />)
    expect(await screen.findByText('需要先注册一个应用')).toBeTruthy()
    expect(screen.queryByText('正在加载可用于测试的应用。')).toBeNull()
  })
})

describe('PlaygroundPage 参数变更作废过期授权结果（Issue #368）', () => {
  it('生成后展示 Authorize URL 与 PKCE', async () => {
    await generateAuthorizeUrl()
    expect(screen.getByText('code_verifier')).toBeTruthy()
    expect(screen.getByText('Authorize URL')).toBeTruthy()
    const link = screen.getByRole('link', { name: /打开授权端点/ })
    expect(link.getAttribute('href')).toContain('redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback')
    expect(link.getAttribute('href')).toContain('scope=openid')
  })

  it('修改 Redirect URI 后清掉授权结果', async () => {
    await generateAuthorizeUrl()
    fireEvent.change(screen.getByLabelText('Redirect URI'), {
      target: { value: 'https://app.example.com/other' },
    })
    await waitFor(() => {
      expect(screen.queryByRole('link', { name: /打开授权端点/ })).toBeNull()
      expect(screen.queryByText('Authorize URL')).toBeNull()
    })
    expect(screen.getByRole('button', { name: '生成授权 URL' })).toBeTruthy()
  })

  it('修改 Scope 后清掉授权结果', async () => {
    await generateAuthorizeUrl()
    fireEvent.change(screen.getByLabelText('Scope'), { target: { value: 'openid profile' } })
    await waitFor(() => {
      expect(screen.queryByRole('link', { name: /打开授权端点/ })).toBeNull()
      expect(screen.queryByText('Authorize URL')).toBeNull()
    })
  })
})
