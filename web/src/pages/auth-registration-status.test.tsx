import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AuthPage } from './auth'
import { installCsrfCookie } from '../test/csrf-cookie'
import type { UserMe } from '../api'

// 注册提交是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

// AuthPage 依赖 useAuth。mock 掉 auth-state，避免 AuthProvider 挂载时额外发出
// /auth/me 请求，污染下面对请求次数的断言。
const authStub = vi.hoisted(() => ({
  profile: null as UserMe | null,
}))

vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: null,
    status: 'unauthenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(authStub.profile),
    clear: () => {},
    logout: () => Promise.resolve(),
  }),
}))

type CapturedRequest = { path: string; body: Record<string, unknown> }

let requests: CapturedRequest[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  window.history.replaceState({}, '', '/register')
  requests = []
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/**
 * 只应答注册状态端点，其余请求记账后返回成功。
 * 状态请求不计入 requests，断言里的次数就等于「实际发出的注册请求数」。
 */
function stubRegistrationStatus(status: unknown, statusOk = true) {
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    if (path === '/api/v1/auth/registration-status') {
      return Promise.resolve(jsonResponse(status, statusOk ? 200 : 500))
    }
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
  })
}

function fillRegisterForm() {
  fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'chenxing_user' } })
  fireEvent.change(screen.getByLabelText('邮箱'), { target: { value: 'user@chenxing.star' } })
  fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
}

function consentCheckbox(): HTMLInputElement {
  return screen.getByRole('checkbox') as HTMLInputElement
}

function registerButton(): HTMLButtonElement {
  return screen.getByRole('button', { name: /创建通行证/ }) as HTMLButtonElement
}

function registerForm(): HTMLFormElement {
  return registerButton().closest('form') as HTMLFormElement
}

describe('AuthPage 注册页如实展示公开注册状态', () => {
  it('enabled=false：提示自助注册未开放并禁用提交', async () => {
    stubRegistrationStatus({ enabled: false, email_verification_required: false })
    render(<AuthPage mode="register" />)
    expect(await screen.findByText('自助注册未开放，请联系管理员创建账号。')).toBeTruthy()
    // fieldset disabled 模式：整表控件不可用，强行提交也发不出注册请求
    expect(registerForm().querySelector('fieldset')?.disabled).toBe(true)
    fireEvent.submit(registerForm())
    expect(requests).toHaveLength(0)
  })

  it('enabled=true 且要求邮箱验证：提示投递能力在建并禁用提交', async () => {
    stubRegistrationStatus({ enabled: true, email_verification_required: true })
    render(<AuthPage mode="register" />)
    expect(await screen.findByText('平台要求邮箱所有权验证，验证投递能力在建，注册暂不可用。')).toBeTruthy()
    expect(registerForm().querySelector('fieldset')?.disabled).toBe(true)
    fireEvent.submit(registerForm())
    expect(requests).toHaveLength(0)
  })

  it('enabled=true 且不要求邮箱验证：现有注册流程不变', async () => {
    stubRegistrationStatus({ enabled: true, email_verification_required: false })
    render(<AuthPage mode="register" />)
    await screen.findByRole('button', { name: /创建通行证/ })
    expect(screen.queryByText('自助注册未开放，请联系管理员创建账号。')).toBeNull()
    expect(registerForm().querySelector('fieldset')?.disabled).toBe(false)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    expect(registerButton().disabled).toBe(false)
    fireEvent.click(registerButton())
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0].path).toBe('/api/v1/users')
  })

  it('状态接口取回失败时不阻塞注册表单，由后端兜底', async () => {
    stubRegistrationStatus({ code: 'internal' }, false)
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    expect(registerButton().disabled).toBe(false)
    fireEvent.click(registerButton())
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0].path).toBe('/api/v1/users')
  })
})
