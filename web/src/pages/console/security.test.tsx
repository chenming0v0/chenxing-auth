import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { StrictMode, type ReactNode } from 'react'
import { AccountManagement } from './security'
import { installCsrfCookie } from '../../test/csrf-cookie'

/**
 * 个人信息页内嵌的 AccountManagement 可选因子绑定（#470）。
 *
 * 无已启用因子时展示登录验证列表及已绑定账户空态；TOTP / Passkey 从本页按需绑定或移除。
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
type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void }

const NONE = { totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }
const TOTP_ON = { totp_enabled: true, passkey_count: 0, available_methods: ['totp'] }
const IDENTITIES = { items: [{ provider: 'github', provider_name: 'GitHub', subject: 'subject-secret', email: 'user@example.com', linked_at: '2026-08-18T10:00:00Z' }] }
const PROVIDERS = [
  { slug: 'github', name: 'GitHub' },
  { slug: 'google', name: 'Google' },
  { slug: 'chenxing-passport', name: '辰星通行证' },
]
const TOTP_START = {
  enrollment_id: 'enroll-totp-1',
  secret_base32: 'JBSWY3DPEHPK3PXP',
  otpauth_url: 'otpauth://totp/Chenxing?secret=JBSWY3DPEHPK3PXP',
}

let requests: CapturedRequest[] = []
let bindingResponse: { authorization_url: string } | null = null
let factorSummary = NONE
let loadFactorSummary: () => Promise<Response>
let identities = { items: [] as typeof IDENTITIES.items }


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

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
}

async function openSecurityTab(): Promise<void> {
  fireEvent.click(await screen.findByRole('tab', { name: '安全设置' }))
  await waitFor(() => expect(screen.queryAllByText('读取中')).toHaveLength(0))
}

function renderAccountManagement(strict = false) {
  const accountManagement = (
    <AccountManagement
      userEmail="user@chenxing.star"
      profileSummary="显示名称：辰星 · 用户名：@chenxing"
      profileAction={<button type="button">修改账户资料</button>}
      emailAction={<button type="button">更改邮箱</button>}
      passwordAction={<a href="#password">修改密码</a>}
    />
  )
  return render(strict ? <StrictMode>{accountManagement}</StrictMode> : accountManagement)
}

beforeEach(() => {
  requests = []
  bindingResponse = null
  factorSummary = NONE
  loadFactorSummary = () => Promise.resolve(jsonResponse(factorSummary))
  identities = { items: [] }
  clearMock.mockReset()

  window.history.replaceState({}, '', '/console/profile')
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    const request = capture(path, init)
    requests.push(request)
    expect(init?.credentials).toBe('include')

    if (path === '/api/v1/auth/external-identities' && request.method === 'GET') {
      return Promise.resolve(jsonResponse(identities))
    }
    if (path === '/api/v1/auth/external-providers' && request.method === 'GET') {
      return Promise.resolve(jsonResponse(PROVIDERS))
    }
    if (path === '/api/v1/auth/external-identities/google/bind' && request.method === 'POST') {
      bindingResponse = { authorization_url: 'https://provider.example/authorize' }
      return Promise.resolve(jsonResponse(bindingResponse))
    }
    if (path === '/api/v1/auth/external-identities/github' && request.method === 'DELETE') {
      identities = { items: [] }
      return Promise.resolve({ ok: true, status: 204, json: async () => undefined } as Response)
    }
    if (path === '/api/v1/auth/security/factors' && request.method === 'GET') {
      return loadFactorSummary()
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

describe('AccountManagement 可选因子（#470）', () => {
  it('默认展示可扩展的账户绑定 Tab，任意后端 provider 自动成为绑定项', async () => {
    renderAccountManagement()
    expect(await screen.findByRole('heading', { name: '账户管理' })).toBeTruthy()
    expect(screen.getByRole('tab', { name: '账户绑定' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByText('user@chenxing.star')).toBeTruthy()
    expect(screen.getByText('辰星通行证')).toBeTruthy()
    expect(screen.getByRole('button', { name: '绑定 辰星通行证' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '绑定 GitHub' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: '注册 Passkey' })).toBeNull()

    const list = requests.find((request) => request.path === '/api/v1/auth/security/factors')
    expect(list).toMatchObject({ method: 'GET' })
    expect(list?.headers.get('X-CSRF-Token')).toBeNull()
  })

  it('切换到安全设置后展示密码、Passkey 和验证器操作', async () => {
    renderAccountManagement()
    await openSecurityTab()

    expect(screen.getByRole('link', { name: '修改密码' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '修改账户资料' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '更改邮箱' })).toBeTruthy()
    expect(screen.getByText('邮箱地址')).toBeTruthy()
    expect(screen.getByRole('button', { name: '注册 Passkey' })).toBeTruthy()
    expect(screen.getByRole('button', { name: '绑定验证器' })).toBeTruthy()
    expect(screen.getByText('当前使用密码登录')).toBeTruthy()
    expect(screen.getByText('没有启用额外验证方式时，密码验证成功会直接建立普通会话。')).toBeTruthy()
  })

  it('缺少 CSRF Cookie 时不发出绑定请求', async () => {
    document.cookie = 'chenxing_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    renderAccountManagement()
    await openSecurityTab()
    fireEvent.click(screen.getByRole('button', { name: '绑定验证器' }))
    expect(await screen.findByText('请求校验失败，请刷新页面后重试。')).toBeTruthy()
    expect(requests.some((request) => request.path.endsWith('/enrollment/start'))).toBe(false)
  })

  it('从安全设置开始并确认 TOTP，写请求携带 Session/CSRF 绑定头', async () => {
    renderAccountManagement()
    await openSecurityTab()
    expect(screen.queryByRole('dialog', { name: '绑定验证器应用' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '绑定验证器' }))

    const totpDialog = await screen.findByRole('dialog', { name: '绑定验证器应用' })
    expect(within(totpDialog).getByLabelText('确认验证码')).toBeTruthy()
    expect(within(totpDialog).getByText('JBSWY3DPEHPK3PXP')).toBeTruthy()
    const start = requests.find((request) => request.path.endsWith('/enrollment/start'))
    expect(start).toMatchObject({ method: 'POST', body: {} })
    expect(start?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')

    fireEvent.change(within(totpDialog).getByLabelText('确认验证码'), { target: { value: '123456' } })
    fireEvent.click(within(totpDialog).getByRole('button', { name: '确认并启用' }))

    await screen.findByText('TOTP 已启用。下次登录将需要验证码。')
    expect(screen.queryByText('当前使用密码登录')).toBeNull()
    const confirm = requests.find((request) => request.path.endsWith('/enrollment/confirm'))
    expect(confirm).toMatchObject({
      method: 'POST',
      body: { enrollment_id: 'enroll-totp-1', code: '123456' },
    })
    expect(confirm?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')
  })

  it('显示回调成功结果并清理回调查询参数', async () => {
    window.history.replaceState({}, '', '/settings/security?external=linked')
    renderAccountManagement()
    expect(await screen.findByText('外部账户已绑定。')).toBeTruthy()
    expect(window.location.search).toBe('')
    expect(window.location.pathname).toBe('/console/profile')
  })

  it('展示外部账户列表，隐藏 subject，并以密码和 CSRF 解除绑定', async () => {
    identities = IDENTITIES
    renderAccountManagement()
    expect(await screen.findByText('GitHub')).toBeTruthy()
    expect(screen.getByText('user@example.com')).toBeTruthy()
    expect(screen.queryByText('subject-secret')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '解除 GitHub 绑定' }))
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'current-password' } })
    fireEvent.click(screen.getByRole('button', { name: '确认解除绑定' }))

    expect(await screen.findByText('GitHub 已解除绑定。')).toBeTruthy()
    const removal = requests.find((request) => request.path === '/api/v1/auth/external-identities/github')
    expect(removal).toMatchObject({ method: 'DELETE', body: { password: 'current-password' } })
    expect(removal?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')
  })

  it('通过受 CSRF 保护的绑定端点启动外部账户绑定', async () => {
    renderAccountManagement()
    fireEvent.click(await screen.findByRole('button', { name: '绑定 Google' }))

    await waitFor(() => {
      const binding = requests.find((request) => request.path === '/api/v1/auth/external-identities/google/bind')
       expect(binding).toMatchObject({ method: 'POST', body: null })
       expect(binding?.headers.get('X-CSRF-Token')).toBe('test-csrf-token')
       expect(bindingResponse).toEqual({ authorization_url: 'https://provider.example/authorize' })
    })
  })
})

describe('AccountManagement 页签键盘导航（#691）', () => {
  it('方向键在两个页签间移动焦点并同时切换面板', async () => {
    renderAccountManagement()
    const bindings = await screen.findByRole('tab', { name: '账户绑定' })
    const security = screen.getByRole('tab', { name: '安全设置' })
    expect(bindings.getAttribute('aria-selected')).toBe('true')
    expect(bindings.tabIndex).toBe(0)
    expect(security.tabIndex).toBe(-1)

    bindings.focus()
    fireEvent.keyDown(bindings, { key: 'ArrowRight' })

    await waitFor(() => expect(screen.getByRole('tab', { name: '安全设置' }).getAttribute('aria-selected')).toBe('true'))
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '安全设置' }))
    expect(screen.getByRole('tab', { name: '安全设置' }).tabIndex).toBe(0)
    expect(screen.getByRole('tab', { name: '账户绑定' }).tabIndex).toBe(-1)
    expect(screen.getByRole('tabpanel').getAttribute('aria-labelledby')).toBe('security-settings-tab')
  })

  it('ArrowLeft 在首个页签上回环到末个页签', async () => {
    renderAccountManagement()
    const bindings = await screen.findByRole('tab', { name: '账户绑定' })
    bindings.focus()
    fireEvent.keyDown(bindings, { key: 'ArrowLeft' })

    await waitFor(() => expect(screen.getByRole('tab', { name: '安全设置' }).getAttribute('aria-selected')).toBe('true'))
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '安全设置' }))
  })

  it('Home / End 跳到首末页签', async () => {
    renderAccountManagement()
    const bindings = await screen.findByRole('tab', { name: '账户绑定' })
    bindings.focus()
    fireEvent.keyDown(bindings, { key: 'End' })

    await waitFor(() => expect(screen.getByRole('tab', { name: '安全设置' }).getAttribute('aria-selected')).toBe('true'))

    fireEvent.keyDown(screen.getByRole('tab', { name: '安全设置' }), { key: 'Home' })
    await waitFor(() => expect(screen.getByRole('tab', { name: '账户绑定' }).getAttribute('aria-selected')).toBe('true'))
    expect(document.activeElement).toBe(screen.getByRole('tab', { name: '账户绑定' }))
  })

  it('非 tabs 模式的按键不改变选中项', async () => {
    renderAccountManagement()
    const bindings = await screen.findByRole('tab', { name: '账户绑定' })
    bindings.focus()
    fireEvent.keyDown(bindings, { key: 'ArrowDown' })
    fireEvent.keyDown(bindings, { key: 'a' })

    expect(screen.getByRole('tab', { name: '账户绑定' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByRole('tab', { name: '安全设置' }).getAttribute('aria-selected')).toBe('false')
  })
})

describe('AccountManagement 安全因子加载状态（#681）', () => {
  it('初始加载失败时显示未知状态，不把未知因子声明为未启用或零凭据', async () => {
    loadFactorSummary = () => Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
    renderAccountManagement()

    expect(await screen.findByText('服务暂时不可用，请稍后重试。')).toBeTruthy()
    await openSecurityTab()

    expect(screen.getAllByText('状态未知')).toHaveLength(4)
    expect(screen.queryByText('基础保护')).toBeNull()
    expect(screen.queryByText('仅密码')).toBeNull()
    expect(screen.queryByText('未启用')).toBeNull()
    expect(screen.queryByText('当前使用密码登录')).toBeNull()
    expect(screen.queryByRole('button', { name: '注册 Passkey' })).toBeNull()
    expect(screen.queryByRole('button', { name: '绑定验证器' })).toBeNull()
  })

  it('旧加载在 enrollment 刷新后才返回时，不覆盖新因子状态', async () => {
    const staleLoad = deferred<Response>()
    let factorLoadCount = 0
    loadFactorSummary = () => {
      factorLoadCount += 1
      return factorLoadCount === 1 ? staleLoad.promise : Promise.resolve(jsonResponse(factorSummary))
    }
    renderAccountManagement(true)

    await waitFor(() => expect(factorLoadCount).toBe(2))
    await openSecurityTab()
    fireEvent.click(await screen.findByRole('button', { name: '绑定验证器' }))
    const totpDialog = await screen.findByRole('dialog', { name: '绑定验证器应用' })
    fireEvent.change(within(totpDialog).getByLabelText('确认验证码'), { target: { value: '123456' } })
    fireEvent.click(within(totpDialog).getByRole('button', { name: '确认并启用' }))

    expect(await screen.findByRole('button', { name: '移除验证器' })).toBeTruthy()
    expect(factorLoadCount).toBe(3)

    await act(async () => {
      staleLoad.resolve(jsonResponse(NONE))
      await staleLoad.promise
    })

    expect(screen.getByRole('button', { name: '移除验证器' })).toBeTruthy()
    expect(screen.queryByRole('button', { name: '绑定验证器' })).toBeNull()
    expect(screen.getByText('安全增强已启用')).toBeTruthy()
    expect(screen.queryByText('当前使用密码登录')).toBeNull()
  })
})
