import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AuthPage } from './auth'

// AuthPage 依赖 useAuth。这里 mock 掉 auth-state，避免 AuthProvider 挂载时额外发出
// /auth/me 与 /admin/bootstrap/status 请求，污染下面对请求 body 的断言。
// 工厂函数内联返回桩对象：vi.mock 的工厂在被 mock 模块首次导入时执行，
// 时机早于本文件顶层 const 初始化，引用外部变量会触发 TDZ 错误。
vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: null,
    status: 'unauthenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(null),
    refreshBootstrap: () => Promise.resolve('ready'),
    clear: () => {},
    logout: () => Promise.resolve(),
  }),
}))

type CapturedRequest = { path: string; body: Record<string, unknown> }

/** 逐次记录 fetch 的路径与 JSON body，用于断言实际发出的字段。 */
let requests: CapturedRequest[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  window.history.replaceState({}, '', '/login')
  requests = []
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/** 填满注册表单的必填项，但不触碰同意复选框。 */
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

describe('AuthPage 注册页服务条款同意（#89）', () => {
  it('同意复选框在页面加载时未勾选', () => {
    render(<AuthPage mode="register" />)
    expect(consentCheckbox().checked).toBe(false)
    expect(screen.getByText('我已阅读并同意《辰星通行证服务条款》与《隐私政策》')).toBeTruthy()
  })

  it('未勾选同意时提交按钮被禁用', () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    expect(registerButton().disabled).toBe(true)
  })

  it('勾选同意后提交按钮启用', () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    expect(consentCheckbox().checked).toBe(true)
    expect(registerButton().disabled).toBe(false)
  })

  it('取消勾选后提交按钮重新禁用', () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    fireEvent.click(consentCheckbox())
    expect(consentCheckbox().checked).toBe(false)
    expect(registerButton().disabled).toBe(true)
  })

  it('未勾选同意时不会发出注册请求', () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(registerButton())
    expect(requests).toHaveLength(0)
  })

  it('勾选同意后提交会发出注册请求', async () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    fireEvent.click(registerButton())
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0].path).toBe('/api/v1/users')
    expect(requests[0].body.username).toBe('chenxing_user')
    expect(requests[0].body.email).toBe('user@chenxing.star')
  })
})

describe('AuthPage 登录页移除失效的 keepLogin 控件（#88）', () => {
  it('登录表单不再渲染「保持登录」复选框', () => {
    render(<AuthPage mode="login" />)
    expect(screen.queryByRole('checkbox')).toBeNull()
    expect(screen.queryByText('在此设备保持登录')).toBeNull()
  })

  it('保留忘记密码入口', () => {
    render(<AuthPage mode="login" />)
    expect(screen.getByText('忘记密码？')).toBeTruthy()
  })

  it('登录请求 body 只包含 identifier 与 password，不含 keep_login', async () => {
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
    fireEvent.click(screen.getByRole('button', { name: /登录 · 进入星门/ }))
    await waitFor(() => expect(requests).toHaveLength(1))
    expect(requests[0].path).toBe('/api/v1/auth/login')
    expect(Object.keys(requests[0].body).sort()).toEqual(['identifier', 'password'])
  })

  it('注册请求 body 不含 keep_login', async () => {
    render(<AuthPage mode="register" />)
    fillRegisterForm()
    fireEvent.click(consentCheckbox())
    fireEvent.click(registerButton())
    await waitFor(() => expect(requests).toHaveLength(1))
    expect('keep_login' in requests[0].body).toBe(false)
  })
})

describe('AuthPage MFA 登录凭证失效恢复（#195）', () => {
  it('login_ticket 失效后可通过「重新登录」回到登录表单，MFA 状态被清理', async () => {
    // 分阶段响应：登录返回待二次验证，随后 TOTP 校验返回 login_ticket 失效
    vi.stubGlobal('fetch', (path: string) => {
      if (path === '/api/v1/auth/login') {
        return Promise.resolve(jsonResponse({ status: 'factor_required', methods: ['totp'] }))
      }
      if (path === '/api/v1/auth/totp/login') {
        return Promise.resolve({ ok: false, status: 400, json: async () => ({ code: 'invalid_login_ticket' }) } as Response)
      }
      return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
    })
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
    fireEvent.click(screen.getByRole('button', { name: /登录 · 进入星门/ }))
    await waitFor(() => expect(screen.getByText('请输入验证器中的 6 位验证码。')).toBeTruthy())

    fireEvent.change(screen.getByLabelText('一次性验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /完成验证/ }))
    await waitFor(() => expect(screen.getByRole('button', { name: /重新登录/ })).toBeTruthy())

    fireEvent.click(screen.getByRole('button', { name: /重新登录/ }))
    // 回到登录表单：MFA 步骤消失、已填凭据保留、失效原因仍可见
    await waitFor(() => expect(screen.getByRole('button', { name: /登录 · 进入星门/ })).toBeTruthy())
    expect(screen.queryByLabelText('一次性验证码')).toBeNull()
    expect((screen.getByLabelText('邮箱或用户名') as HTMLInputElement).value).toBe('user@chenxing.star')
    expect(screen.getByText('验证流程已失效，请重新登录。')).toBeTruthy()
  })

  it('MFA 期间普通校验失败不触发恢复视图，仅展示错误文案', async () => {
    vi.stubGlobal('fetch', (path: string) => {
      if (path === '/api/v1/auth/login') {
        return Promise.resolve(jsonResponse({ status: 'factor_required', methods: ['totp'] }))
      }
      if (path === '/api/v1/auth/totp/login') {
        return Promise.resolve({ ok: false, status: 400, json: async () => ({ code: 'invalid_factor' }) } as Response)
      }
      return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
    })
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
    fireEvent.click(screen.getByRole('button', { name: /登录 · 进入星门/ }))
    await waitFor(() => expect(screen.getByLabelText('一次性验证码')).toBeTruthy())

    fireEvent.change(screen.getByLabelText('一次性验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /完成验证/ }))
    await waitFor(() => expect(screen.getByText('验证码不正确，请重试。')).toBeTruthy())
    expect(screen.queryByRole('button', { name: /重新登录/ })).toBeNull()
    expect(screen.getByLabelText('一次性验证码')).toBeTruthy()
  })
})
