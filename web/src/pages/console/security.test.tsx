import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ConsoleSecurity } from './security'
import { installCsrfCookie } from '../../test/csrf-cookie'

/**
 * ConsoleSecurity 可选因子绑定（#470）。
 *
 * 无已启用因子时只展示密码登录空态；TOTP / Passkey 从本页按需绑定或移除。
 * 写操作走真实 apiFetch：Session Cookie（credentials: include）+ CSRF Cookie + X-CSRF-Token。
 * 只 stub 公共 fetch 边界，不改生产 UI。
 */
installCsrfCookie()

const { clearMock } = vi.hoisted(() => ({
  clearMock: vi.fn(),
}))

vi.mock('../../auth-state', () => ({
  useAuth: () => ({
    user: {
      id: 1, username: 'chenxing', email: 'user@chenxing.star', display_name: '辰星',
      status: 'active', role: 'user', current_session_expires_at: '2099-01-01T00:00:00Z',
      avatar_updated_at: null,
    },
    status: 'authenticated',
    clear: clearMock,
  }),
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

type CapturedRequest = { path: string; method: string; body: Record<string, unknown> | null; headers: Headers }

const NONE = { totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }
const TOTP_ON = { totp_enabled: true, passkey_count: 0, available_methods: ['totp'] }
const TOTP_START = {
  enrollment_id: 'enroll-totp-1',
  secret_base32: 'JBSWY3DPEHPK3PXP',
  otpauth_url: 'otpauth://totp/Chenxing?secret=JBSWY3DPEHPK3PXP',
}

let requests: CapturedRequest[] = []
let factorSummary = NONE

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function capture(path: string, init?: RequestInit): CapturedRequest {
  const raw = typeof init?.body === 'string' ? init.body : ''
  return {
    path,
    method: (init?.method ?? 'GET').toUpperCase(),
    body: raw ? JSON.parse(raw) as Record<string, unknown> : null,
    headers: new Headers(init?.headers),
  }
}

beforeEach(() => {
  requests = []
  factorSummary = NONE
  clearMock.mockReset()
  window.history.replaceState({}, '', '/console/security')
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    const request = capture(path, init)
    requests.push(request)
    expect(init?.credentials).toBe('include')

    if (path === '/api/v1/auth/security/factors' && request.method === 'GET') {
      return Promise.resolve(jsonResponse(factorSummary))
    }
    if (path === '/api/v1/auth/security/totp/enrollment/start' && request.method === 'POST') {
      return Promise.resolve(jsonResponse(TOTP_START))
    }
    if (path === '/api/v1/auth/security/totp/enrollment/confirm' && request.method === 'POST') {
      factorSummary = TOTP_ON
      return Promise.resolve(jsonResponse({ method: 'totp', enabled: true }))
    }
    if (path === '/api/v1/auth/security/factors/totp' && request.method === 'DELETE') {
      return Promise.resolve(jsonResponse({ method: 'totp', removed: 1, credentials_revoked: true }))
    }
    return Promise.reject(new Error(`unexpected request: ${request.method} ${path}`))
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ConsoleSecurity 可选因子（#470）', () => {
  it('无已启用因子时展示密码登录空态，列表请求不带 CSRF', async () => {
    render(<ConsoleSecurity />)
    expect(await screen.findByText('当前使用密码登录')).toBeTruthy()
    expect(screen.getByText('没有启用因子时，密码验证成功会直接建立普通会话。')).toBeTruthy()
    expect(screen.getByRole('button', { name: '启用 TOTP' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '注册 Passkey' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: '移除 TOTP' })).toBeNull()

    const list = requests.find((request) => request.path === '/api/v1/auth/security/factors')
    expect(list).toMatchObject({ method: 'GET' })
    expect(list?.headers.get('X-CSRF-Token')).toBeNull()
  })

  it('缺少 CSRF Cookie 时不发出绑定请求', async () => {
    document.cookie = 'chenxing_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    render(<ConsoleSecurity />)
    await screen.findByRole('button', { name: '启用 TOTP' })
    fireEvent.click(screen.getByRole('button', { name: '启用 TOTP' }))
    expect(await screen.findByText('请求校验失败，请刷新页面后重试。')).toBeTruthy()
    expect(requests.some((request) => request.path.endsWith('/enrollment/start'))).toBe(false)
  })

  it('从安全设置开始并确认 TOTP，写请求携带 Session/CSRF 绑定头', async () => {
    render(<ConsoleSecurity />)
    await screen.findByRole('button', { name: '启用 TOTP' })
    fireEvent.click(screen.getByRole('button', { name: '启用 TOTP' }))

    expect(await screen.findByLabelText('确认验证码')).toBeTruthy()
    expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeTruthy()
    const start = requests.find((request) => request.path.endsWith('/enrollment/start'))
    expect(start).toMatchObject({ method: 'POST', body: {} })
    expect(start?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')

    fireEvent.change(screen.getByLabelText('确认验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: '确认并启用' }))

    await screen.findByText('TOTP 已启用。下次登录将需要验证码。')
    expect(screen.queryByText('当前使用密码登录')).toBeNull()
    const confirm = requests.find((request) => request.path.endsWith('/enrollment/confirm'))
    expect(confirm).toMatchObject({
      method: 'POST',
      body: { enrollment_id: 'enroll-totp-1', code: '123456' },
    })
    expect(confirm?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')
  })

  it('密码确认后移除 TOTP，撤销本地会话并回到登录页', async () => {
    factorSummary = TOTP_ON
    render(<ConsoleSecurity />)
    fireEvent.click(await screen.findByRole('button', { name: '移除 TOTP' }))
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'current-password' } })
    fireEvent.click(screen.getByRole('button', { name: '确认移除' }))

    await waitFor(() => expect(clearMock).toHaveBeenCalledTimes(1))
    expect(`${window.location.pathname}${window.location.search}`).toBe('/login?returnTo=%2Fconsole%2Fsecurity')
    const removal = requests.find((request) => request.path === '/api/v1/auth/security/factors/totp')
    expect(removal).toMatchObject({ method: 'DELETE', body: { password: 'current-password' } })
    expect(removal?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')
  })
})
