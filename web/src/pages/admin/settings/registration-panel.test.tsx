import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { ISSUER_GATE_MESSAGE, RegistrationPanel } from './registration-panel'

// 保存走 PUT /api/v1/admin/settings/registration 的 apiFetch，需要 CSRF cookie 才能发出。
installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

type CapturedRequest = { path: string; method: string; body?: Record<string, unknown> }

let requests: CapturedRequest[] = []

/**
 * 面板挂载时会拉两个端点：自身设置 + IssuerPanel 同款的 Issuer 运行时状态。
 * issuerPhase 决定闸门是否就绪；putStatus/putCode 用来模拟保存被 503 拒绝。
 */
function stubFetch(options: {
  registration?: Record<string, unknown>
  issuerPhase?: 'awaiting_issuer' | 'issuer_loaded' | 'issuer_invalid'
  putStatus?: number
  putCode?: string
} = {}) {
  const registration = options.registration ?? { enabled: false, email_verification_required: false, invitation_code_required: false }
  requests = []
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : undefined
    requests.push({ path: String(path), method, body: raw ? JSON.parse(raw) as Record<string, unknown> : undefined })
    if (method === 'GET' && path === '/api/v1/admin/settings/registration') {
      return Promise.resolve(jsonResponse(registration))
    }
    if (method === 'GET' && path === '/api/v1/admin/settings/issuer') {
      const phase = options.issuerPhase ?? 'awaiting_issuer'
      return Promise.resolve(jsonResponse({
        persisted: null,
        loaded: phase === 'issuer_loaded'
          ? { value: 'https://auth.example.com', generation: 1, updated_at: '2026-01-01T00:00:00Z' }
          : null,
        phase,
      }))
    }
    if (method === 'PUT' && path === '/api/v1/admin/settings/registration') {
      if (options.putStatus && options.putStatus >= 400) {
        return Promise.resolve(jsonResponse({ code: options.putCode ?? 'internal' }, options.putStatus))
      }
      // 保存接口回显完整设置对象：面板据此就地刷新，不需要再 GET 一次。
      return Promise.resolve(jsonResponse(raw ? JSON.parse(raw) : registration))
    }
    return Promise.resolve(jsonResponse({}))
  })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function enableToggle(): HTMLElement {
  return screen.getByRole('switch', { name: '开启公开注册' })
}

describe('RegistrationPanel 加载与保存', () => {
  it('保存按钮是真正的 submit 按钮，发出与草稿一致的 PUT', async () => {
    stubFetch({ issuerPhase: 'issuer_loaded' })
    render(<RegistrationPanel onMessage={vi.fn()} onDirtyChange={() => {}} />)
    fireEvent.click(await screen.findByRole('switch', { name: '开启公开注册' }))
    fireEvent.click(screen.getByRole('button', { name: '保存公开注册设置' }))

    await waitFor(() => {
      expect(requests.some((request) => request.method === 'PUT' && request.path === '/api/v1/admin/settings/registration')).toBe(true)
    })
    const put = requests.find((request) => request.method === 'PUT')
    expect(put?.body).toMatchObject({ enabled: true, email_verification_required: false })
  })

  it('编辑后上报 dirty，保存成功后回落 false', async () => {
    stubFetch({ issuerPhase: 'issuer_loaded' })
    const dirtyReports: boolean[] = []
    render(<RegistrationPanel onMessage={vi.fn()} onDirtyChange={(dirty) => dirtyReports.push(dirty)} />)
    fireEvent.click(await screen.findByRole('switch', { name: '要求邮箱所有权验证' }))
    await waitFor(() => expect(dirtyReports).toContain(true))

    fireEvent.click(screen.getByRole('button', { name: '保存公开注册设置' }))
    await waitFor(() => expect(dirtyReports[dirtyReports.length - 1]).toBe(false))
  })

  it('保存被 503 issuer_not_configured 拒绝时以警告上报统一文案', async () => {
    stubFetch({ issuerPhase: 'issuer_loaded', putStatus: 503, putCode: 'issuer_not_configured' })
    const onMessage = vi.fn()
    render(<RegistrationPanel onMessage={onMessage} onDirtyChange={() => {}} />)
    fireEvent.click(await screen.findByRole('switch', { name: '开启公开注册' }))
    fireEvent.click(screen.getByRole('button', { name: '保存公开注册设置' }))

    await waitFor(() => expect(onMessage).toHaveBeenCalledWith(ISSUER_GATE_MESSAGE, 'warning'))
  })
})

describe('RegistrationPanel Issuer 闸门', () => {
  it('issuer 未就绪时常驻警告，拨向开启被拦回并保持关闭', async () => {
    stubFetch({ issuerPhase: 'awaiting_issuer' })
    const onMessage = vi.fn()
    render(<RegistrationPanel onMessage={onMessage} onDirtyChange={() => {}} />)
    await screen.findByRole('switch', { name: '开启公开注册' })
    expect(screen.getByText(ISSUER_GATE_MESSAGE)).toBeTruthy()

    fireEvent.click(enableToggle())
    expect(enableToggle().getAttribute('aria-checked')).toBe('false')
    expect(onMessage).toHaveBeenCalledWith(ISSUER_GATE_MESSAGE, 'warning')
  })

  it('issuer 运行时无效同样视为未就绪', async () => {
    stubFetch({ issuerPhase: 'issuer_invalid' })
    render(<RegistrationPanel onMessage={vi.fn()} onDirtyChange={() => {}} />)
    await screen.findByRole('switch', { name: '开启公开注册' })
    expect(screen.getByText(ISSUER_GATE_MESSAGE)).toBeTruthy()
  })

  it('issuer 就绪时无闸门警告，可正常开启', async () => {
    stubFetch({ issuerPhase: 'issuer_loaded' })
    render(<RegistrationPanel onMessage={vi.fn()} onDirtyChange={() => {}} />)
    await screen.findByRole('switch', { name: '开启公开注册' })
    expect(screen.queryByText(ISSUER_GATE_MESSAGE)).toBeNull()

    fireEvent.click(enableToggle())
    expect(enableToggle().getAttribute('aria-checked')).toBe('true')
  })
})
