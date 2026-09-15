import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { AppLinksWorkspace } from './app-links'

installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('AppLinksWorkspace', () => {
  it('列出已登记声明并提交覆盖', async () => {
    const requests: Array<{ path: string; method?: string; body?: string }> = []
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      requests.push({ path, method: init?.method, body: typeof init?.body === 'string' ? init.body : undefined })
      if (path === '/api/v1/admin/app-links') {
        return Promise.resolve(jsonResponse([{
          client_id: 'cx-1',
          numeric_app_id: 1,
          client_name: 'termux-chrome',
          package_name: 'com.chengming.termux',
          sha256_cert_fingerprints: ['AA:BB'],
        }]))
      }
      return Promise.resolve(jsonResponse({
        client_id: 'cx-1',
        numeric_app_id: 1,
        client_name: 'termux-chrome',
        package_name: 'com.chengming.termux',
        sha256_cert_fingerprints: ['AA:BB', 'CC:DD'],
      }))
    })

    render(<AppLinksWorkspace />)
    expect(await screen.findByText('termux-chrome')).toBeTruthy()
    expect(screen.getByText('com.chengming.termux')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    fireEvent.click(screen.getByRole('button', { name: '保存声明' }))
    expect(requests.some((request) => request.method === 'PUT' && request.path.includes('/api/v1/admin/app-links/cx-1'))).toBe(true)
  })
})
