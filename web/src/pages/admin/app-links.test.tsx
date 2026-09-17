import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { AdminAppLinks, AppLinksWorkspace } from './app-links'

installCsrfCookie()

const { mockAccess } = vi.hoisted(() => ({
  mockAccess: {
    data: {
      user_id: 1,
      username: 'owner',
      role: 'owner' as 'owner' | 'admin',
      permissions: ['manage_issuer'],
      status: 'active',
    },
    loading: false,
    error: '',
  },
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./shared')>()
  return {
    ...actual,
    useAdminAccess: () => mockAccess,
  }
})

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const LINK = {
  client_id: 'cx-1',
  numeric_app_id: 1,
  client_name: 'termux-chrome',
  package_name: 'com.chengming.termux',
  sha256_cert_fingerprints: ['AA:BB'],
}

const PLATFORM = {
  id: 1,
  numeric_app_id: 1,
  client_id: 'cx-1',
  client_name: 'termux-chrome',
  redirect_uris: ['https://example.com/cb'],
  scopes: ['openid'],
  status: 'active',
  auth_method: 'none',
  quota_exempt: true,
}

beforeEach(() => {
  mockAccess.data = {
    user_id: 1,
    username: 'owner',
    role: 'owner',
    permissions: ['manage_issuer'],
    status: 'active',
  }
  mockAccess.loading = false
  mockAccess.error = ''
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function stubList(extra?: (path: string, init?: RequestInit) => Response | undefined) {
  const requests: Array<{ path: string; method?: string; body?: string }> = []
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const url = String(path)
    requests.push({ path: url, method: init?.method, body: typeof init?.body === 'string' ? init.body : undefined })
    const override = extra?.(url, init)
    if (override) return Promise.resolve(override)
    if (url === '/api/v1/admin/app-links') return Promise.resolve(jsonResponse([LINK]))
    if (url.startsWith('/api/v1/admin/clients')) return Promise.resolve(jsonResponse([PLATFORM]))
    if (url === '/.well-known/openid-configuration') {
      return Promise.resolve(jsonResponse({ issuer: 'https://issuer.example' }))
    }
    return Promise.resolve(jsonResponse({ ...LINK, sha256_cert_fingerprints: ['AA:BB', 'CC:DD'] }))
  })
  return requests
}

describe('AdminAppLinks 权限门', () => {
  it('没有 manage_issuer 时不加载声明列表', () => {
    mockAccess.data = {
      user_id: 2,
      username: 'admin',
      role: 'admin',
      permissions: ['manage_clients'],
      status: 'active',
    }
    const requests = stubList()
    render(<AdminAppLinks />)
    expect(screen.getByText(/没有 `manage_issuer` 权限/)).toBeTruthy()
    expect(screen.queryByText('termux-chrome')).toBeNull()
    expect(requests.some((request) => request.path === '/api/v1/admin/app-links')).toBe(false)
  })

  it('Owner 看到软件链接说明和已登记列表', async () => {
    stubList()
    render(<AdminAppLinks />)
    expect(screen.getByText('软件链接')).toBeTruthy()
    expect(screen.getByText(/只给本实例官方 Android 应用发布本域名的软件链接声明/)).toBeTruthy()
    expect(await screen.findByText('termux-chrome')).toBeTruthy()
  })
})

describe('AppLinksWorkspace', () => {
  it('列出已登记声明；未打开抽屉时没有行内登记表单', async () => {
    stubList()
    render(<AppLinksWorkspace />)
    expect(await screen.findByText('termux-chrome')).toBeTruthy()
    expect(screen.getByText('com.chengming.termux')).toBeTruthy()
    expect(screen.getByRole('button', { name: '登记软件' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: '保存声明' })).toBeNull()
    expect(screen.queryByText('登记或覆盖')).toBeNull()
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('点编辑后打开只读客户端抽屉并提交原来的 PUT', async () => {
    const requests = stubList()
    render(<AppLinksWorkspace />)
    expect(await screen.findByText('termux-chrome')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByText('编辑软件链接')).toBeTruthy()
    expect(screen.queryByRole('combobox', { name: '官方应用' })).toBeNull()
    expect(screen.getByText('这条声明绑定的软件，不能更改。')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '保存声明' }))
    await waitFor(() => {
      expect(requests.some((request) => request.method === 'PUT' && request.path.includes('/api/v1/admin/app-links/cx-1'))).toBe(true)
    })
  })

  it('点登记软件打开选择官方客户端的抽屉', async () => {
    stubList()
    render(<AppLinksWorkspace />)
    await screen.findByText('termux-chrome')
    fireEvent.click(screen.getByRole('button', { name: '登记软件' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByText('登记软件链接')).toBeTruthy()
    const trigger = await screen.findByRole('combobox', { name: '官方应用' })
    await waitFor(() => expect((trigger as HTMLButtonElement).disabled).toBe(false))
    fireEvent.click(trigger)
    expect(await screen.findByRole('option', { name: 'termux-chrome · cx-1' })).toBeTruthy()
    expect(screen.queryByLabelText('Client ID')).toBeNull()
  })
})
