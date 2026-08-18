import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { IssuerPanel } from './issuer-panel'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

describe('IssuerPanel loading failure', () => {
  beforeEach(() => {
    let attempts = 0
    vi.stubGlobal('fetch', () => {
      attempts += 1
      if (attempts === 1) return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
      return Promise.resolve(jsonResponse({
        persisted: null,
        loaded: null,
        phase: 'awaiting_issuer',
      }))
    })
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('shows a retry state and restores the form after a successful reload', async () => {
    const onMessage = vi.fn()
    render(<IssuerPanel onMessage={onMessage} onDirtyChange={() => {}} />)

    expect(await screen.findByText('Issuer 设置暂时无法加载。')).toBeTruthy()
    expect(screen.queryByLabelText('Issuer 根 URL')).toBeNull()
    expect(onMessage).toHaveBeenCalledWith('服务暂时不可用，请稍后重试。', 'warning')

    fireEvent.click(screen.getByRole('button', { name: '重新加载 Issuer 设置' }))

    await waitFor(() => expect(screen.getByLabelText('Issuer 根 URL')).toBeTruthy())
    expect(screen.queryByText('Issuer 设置暂时无法加载。')).toBeNull()
  })
})

describe('IssuerPanel initial configuration', () => {
  // 保存走 PUT /api/v1/admin/settings/issuer 的 apiFetch，需要 CSRF cookie 才能发出。
  installCsrfCookie()

  type CapturedRequest = { path: string; method: string; body?: Record<string, unknown> }
  let requests: CapturedRequest[] = []

  beforeEach(() => {
    requests = []
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      const raw = typeof init?.body === 'string' ? init.body : undefined
      requests.push({ path: String(path), method, body: raw ? JSON.parse(raw) as Record<string, unknown> : undefined })
      if (method === 'GET') {
        return Promise.resolve(jsonResponse({
          persisted: null,
          loaded: null,
          phase: 'awaiting_issuer',
        }))
      }
      return Promise.resolve(jsonResponse(raw ? JSON.parse(raw) : {}))
    })
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  // 回归：保存按钮必须是真正的 submit 按钮。Button 组件默认 type="button"，
  // 漏传 type="submit" 时点击不会触发 form onSubmit，保存请求永远发不出去。
  it('sends the PUT when the save button is clicked', async () => {
    render(<IssuerPanel onMessage={vi.fn()} onDirtyChange={() => {}} />)
    const input = await screen.findByLabelText('Issuer 根 URL')

    fireEvent.change(input, { target: { value: 'https://auth.example.com' } })
    fireEvent.click(screen.getByRole('button', { name: '保存 Issuer' }))

    await waitFor(() => {
      expect(requests.some((request) => request.method === 'PUT' && request.path === '/api/v1/admin/settings/issuer')).toBe(true)
    })
    const put = requests.find((request) => request.method === 'PUT')
    expect(put?.body).toMatchObject({
      value: 'https://auth.example.com',
      expected_generation: 0,
      confirm: false,
    })
  })
})
