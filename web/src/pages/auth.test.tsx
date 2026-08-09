import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AuthPage, safeReturnTo } from './auth'
import { navigate } from '../router'
import type { UserMe } from '../api'

// AuthPage 依赖 useAuth。这里 mock 掉 auth-state，避免 AuthProvider 挂载时额外发出
// /auth/me 与 /admin/bootstrap/status 请求，污染下面对请求 body 的断言。
// 桩的可变部分放在 vi.hoisted 里：vi.mock 的工厂在被 mock 模块首次导入时执行，
// 时机早于本文件顶层 const 初始化，直接引用普通顶层变量会触发 TDZ 错误。
const authStub = vi.hoisted(() => ({
  /** 登录成功后 refresh() 返回的资料；null 表示「登录未完成」。 */
  profile: null as UserMe | null,
  /** #270 的回归断言用：绑定失败时不得调用 clear()。 */
  clearCalls: 0,
}))

vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: null,
    status: 'unauthenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(authStub.profile),
    refreshBootstrap: () => Promise.resolve('ready'),
    clear: () => { authStub.clearCalls += 1 },
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
  authStub.profile = null
  authStub.clearCalls = 0
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

  it('忘记密码改为联系管理员的静态引导，不再是伪链接（#240）', () => {
    render(<AuthPage mode="login" />)
    expect(screen.getByText('忘记密码？请联系管理员重置。')).toBeTruthy()
    // 后端无自助重置流程：不允许渲染成可点击的链接或按钮
    expect(screen.queryByRole('link', { name: /忘记密码/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /忘记密码/ })).toBeNull()
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

describe('AuthPage 提交互斥（#219）', () => {
  it('busy 尚未重渲染时重复提交登录也只发出一个请求', async () => {
    let rejectLogin!: (reason: unknown) => void
    const loginRequest = new Promise<Response>((_, reject) => { rejectLogin = reject })
    const fetchMock = vi.fn((path: string) => path === '/api/v1/auth/login'
      ? loginRequest
      : Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' })))
    vi.stubGlobal('fetch', fetchMock)
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })

    const form = screen.getByRole('button', { name: /登录 · 进入星门/ }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)
    expect(fetchMock).toHaveBeenCalledTimes(1)

    rejectLogin(new Error('request failed'))
    await waitFor(() => expect(screen.getByText('网络连接不可用，请稍后重试。')).toBeTruthy())
  })

  it('MFA 验证提交复用同一同步锁，失败后仍可再次提交', async () => {
    let rejectTotp!: (reason: unknown) => void
    let totpCalls = 0
    const totpRequest = new Promise<Response>((_, reject) => { rejectTotp = reject })
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/v1/auth/login') return Promise.resolve(jsonResponse({ status: 'factor_required', methods: ['totp'] }))
      if (path === '/api/v1/auth/totp/login') {
        totpCalls += 1
        return totpRequest
      }
      return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
    })
    vi.stubGlobal('fetch', fetchMock)
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
    fireEvent.submit(screen.getByRole('button', { name: /登录 · 进入星门/ }).closest('form') as HTMLFormElement)
    await waitFor(() => expect(screen.getByLabelText('一次性验证码')).toBeTruthy())

    fireEvent.change(screen.getByLabelText('一次性验证码'), { target: { value: '123456' } })
    const totpForm = screen.getByRole('button', { name: /完成验证/ }).closest('form') as HTMLFormElement
    fireEvent.submit(totpForm)
    fireEvent.submit(totpForm)
    expect(totpCalls).toBe(1)

    rejectTotp(new Error('totp request failed'))
    await waitFor(() => expect(screen.getByText('网络连接不可用，请稍后重试。')).toBeTruthy())
    fireEvent.submit(totpForm)
    await waitFor(() => expect(totpCalls).toBe(2))
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

describe('AuthPage returnTo 同源校验（#228）', () => {
  function decodedReturnTo(raw: string): string | null {
    return new URLSearchParams(`returnTo=${raw}`).get('returnTo')
  }

  it('拒绝 URL 解析会转成 authority 的反斜杠路径', () => {
    expect(safeReturnTo('/\\evil.com')).toBe('/console')
  })

  it.each([
    '%2F%5Cevil.com',
    '%2F%2Fevil.com',
  ])('拒绝 URLSearchParams 解码后的协议相对攻击地址：%s', (encoded) => {
    expect(safeReturnTo(decodedReturnTo(encoded))).toBe('/console')
  })

  it('不会对 URLSearchParams 解码后的双重编码路径再次解码', () => {
    expect(safeReturnTo(decodedReturnTo('%252F%255Cevil.com'))).toBe('/%2F%5Cevil.com')
  })

  it.each(['/console/%', '/console/%ZZ', '/console?tab=%GG'])('拒绝畸形百分号编码：%s', (value) => {
    expect(safeReturnTo(value)).toBe('/console')
  })

  it('拒绝同源 URL 中的 userinfo 凭据', () => {
    const credentialed = new URL('/console', window.location.origin)
    credentialed.username = 'user'
    credentialed.password = 'secret'
    expect(safeReturnTo(credentialed.href)).toBe('/console')
  })

  it('保留同源相对路径的 query 和 hash，并返回 SPA navigate 可用的路径', () => {
    const target = safeReturnTo(decodedReturnTo('%2Fconsole%2Fsettings%3Ftab%3Dsecurity%26mode%3Dcompact%23sessions'))
    expect(target).toBe('/console/settings?tab=security&mode=compact#sessions')

    navigate(target)
    expect(window.location.pathname).toBe('/console/settings')
    expect(window.location.search).toBe('?tab=security&mode=compact')
    expect(window.location.hash).toBe('#sessions')
  })
})

describe('AuthPage 标题层级（#226）', () => {
  it.each([
    ['login', '统一登录'],
    ['register', '创建辰星通行证'],
  ] as const)('%s 页渲染唯一 h1：%s', (mode, title) => {
    render(<AuthPage mode={mode} />)
    // AuthShell/顶栏不贡献任何标题，整页必须恰好一个 h1（无跳级、无重复）
    expect(screen.getAllByRole('heading')).toHaveLength(1)
    expect(screen.getByRole('heading', { level: 1, name: title })).toBeTruthy()
  })
})

/**
 * #270：登录成功但绑定失败不得清除会话。
 *
 * 旧行为在绑定失败时调用 clear()，把已登录用户打回未认证态；登录页随即
 * 再次把他送进授权流程，形成「登录成功 → 绑定失败 → 视为未登录 → 再登录」
 * 的 401 循环。现在保留会话、就地展示原因。
 */
describe('AuthPage OAuth 绑定失败不清除会话（#270）', () => {
  const PROFILE: UserMe = {
    id: 1,
    username: 'chenxing',
    email: 'user@chenxing.star',
    display_name: null,
    status: 'active',
    role: 'user',
    current_session_expires_at: '2099-01-01T00:00:00Z',
    avatar_updated_at: null,
  }

  /**
   * 带 request_id 打开登录页并提交一次成功登录，bind 的响应由入参决定。
   * bind 是状态变更请求，需要 CSRF cookie 才能发出；由 src/test/setup.ts 统一注入。
   */
  function submitLoginWithRequestId(bindResponse: Response) {
    window.history.replaceState({}, '', '/login?request_id=req-270')
    authStub.profile = PROFILE
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (path.endsWith('/bind')) return Promise.resolve(bindResponse)
      return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
    })
    render(<AuthPage mode="login" />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@chenxing.star' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
    fireEvent.click(screen.getByRole('button', { name: /登录 · 进入星门/ }))
  }

  it('绑定失败时保留会话、留在登录页展示原因', async () => {
    submitLoginWithRequestId({
      ok: false,
      status: 400,
      json: async () => ({ code: 'authorization_request_expired' }),
    } as Response)

    await waitFor(() => expect(screen.getByText('授权请求已过期，请重新发起。')).toBeTruthy())
    // 核心回归：会话必须保留，否则登录页会再次把用户送进授权流程形成循环。
    expect(authStub.clearCalls).toBe(0)
    expect(window.location.pathname).toBe('/login')
  })

  it('holder 不匹配时同样保留会话，只展示可操作的文案', async () => {
    submitLoginWithRequestId({
      ok: false,
      status: 403,
      json: async () => ({ code: 'authorization_holder_invalid' }),
    } as Response)

    await waitFor(() => expect(screen.getByText(/不是在当前浏览器发起的/)).toBeTruthy())
    expect(authStub.clearCalls).toBe(0)
  })

  it('绑定成功后带着 request_id 跳转授权确认页', async () => {
    submitLoginWithRequestId({ ok: true, status: 204, json: async () => undefined } as Response)

    await waitFor(() => expect(window.location.pathname).toBe('/oauth/consent'))
    expect(new URLSearchParams(window.location.search).get('request_id')).toBe('req-270')
    expect(authStub.clearCalls).toBe(0)
  })
})
