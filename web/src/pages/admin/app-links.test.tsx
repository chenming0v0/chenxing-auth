import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { AppLinksWorkspace } from './app-links'

installCsrfCookie()

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

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

function stubList(extra?: (path: string, init?: RequestInit) => Response | undefined) {
  const requests: Array<{ path: string; method?: string; body?: string }> = []
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    requests.push({ path, method: init?.method, body: typeof init?.body === 'string' ? init.body : undefined })
    const override = extra?.(path, init)
    if (override) return Promise.resolve(override)
    if (path === '/api/v1/admin/app-links') return Promise.resolve(jsonResponse([LINK]))
    return Promise.resolve(jsonResponse({ ...LINK, sha256_cert_fingerprints: ['AA:BB', 'CC:DD'] }))
  })
  return requests
}

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

  it('点编辑后打开抽屉并提交原来的 PUT', async () => {
    const requests = stubList()
    render(<AppLinksWorkspace />)
    expect(await screen.findByText('termux-chrome')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByText('编辑软件链接')).toBeTruthy()
    expect((screen.getByLabelText('Client ID') as HTMLInputElement).value).toBe('cx-1')
    expect((screen.getByLabelText('Client ID') as HTMLInputElement).readOnly).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: '保存声明' }))
    await waitFor(() => {
      expect(requests.some((request) => request.method === 'PUT' && request.path.includes('/api/v1/admin/app-links/cx-1'))).toBe(true)
    })
  })

  it('点登记软件打开空抽屉，Client ID 可填', async () => {
    stubList()
    render(<AppLinksWorkspace />)
    await screen.findByText('termux-chrome')
    fireEvent.click(screen.getByRole('button', { name: '登记软件' }))
    expect(await screen.findByRole('dialog')).toBeTruthy()
    expect(screen.getByText('登记软件链接')).toBeTruthy()
    const clientId = screen.getByLabelText('Client ID') as HTMLInputElement
    expect(clientId.value).toBe('')
    expect(clientId.readOnly).toBe(false)
  })
})
