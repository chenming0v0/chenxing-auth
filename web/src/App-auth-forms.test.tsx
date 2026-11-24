import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'
import App from './App'
import { clearApiCache } from './api'
import { replaceUrl } from './router'
import { installCsrfCookie } from './test/csrf-cookie'

vi.mock('./components/shells', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./components/shells')>()),
  AuthShell: ({ children }: { children: ReactNode }) => <>{children}</>,
  AuthPanel: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

vi.mock('./auth-state', async (importOriginal) => {
  const original = await importOriginal<typeof import('./auth-state')>()
  function StatusProbe() {
    return <output aria-label="初始认证状态">{original.useAuth().status}</output>
  }
  return {
    ...original,
    AuthProvider: ({ children }: { children: ReactNode }) => <original.AuthProvider>{children}<StatusProbe /></original.AuthProvider>,
  }
})

installCsrfCookie()

const AUTH_SYNC_KEY = 'chenxing-auth-sync-event'

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function deferredResponse() {
  let resolve!: (response: Response) => void
  const promise = new Promise<Response>((done) => { resolve = done })
  return { promise, resolve }
}

function installNetwork(initial: ReturnType<typeof deferredResponse>) {
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn((path: string) => {
    calls.push(path)
    if (path === '/api/v1/auth/me') return initial.promise
    if (path === '/api/v1/auth/registration-status') {
      return Promise.resolve(jsonResponse({ enabled: true, email_verification_required: false, invitation_code_required: false }))
    }
    if (path === '/api/v1/auth/login') return Promise.resolve(jsonResponse({ status: 'factor_required', methods: ['totp', 'passkey'] }))
    if (path === '/api/v1/admin/bootstrap') return Promise.resolve(jsonResponse({}, 201))
    throw new Error(`unexpected request: ${path}`)
  }))
  return calls
}

async function finishInitial401(initial: ReturnType<typeof deferredResponse>) {
  await act(async () => {
    initial.resolve(jsonResponse({ code: 'unauthorized' }, 401))
    await initial.promise
  })
  await waitFor(() => expect(screen.getByLabelText('初始认证状态').textContent).toBe('unauthenticated'))
  expect(window.localStorage.getItem(AUTH_SYNC_KEY)).toBeNull()
}

beforeEach(() => {
  window.localStorage.removeItem(AUTH_SYNC_KEY)
  replaceUrl('/login')
})

afterEach(() => {
  cleanup()
  clearApiCache()
  vi.unstubAllGlobals()
  window.localStorage.removeItem(AUTH_SYNC_KEY)
  replaceUrl('/login')
})

describe('公开认证表单保留首屏输入（#745）', () => {
  it.each([
    ['/login', '邮箱或用户名', 'user@example.test'],
    ['/register', '邮箱', 'new-user@example.test'],
    ['/bootstrap', '管理员用户名', 'new-owner'],
  ])('%s 的延迟首屏 401 不重挂已经输入的表单', async (path, label, value) => {
    replaceUrl(path)
    const initial = deferredResponse()
    installNetwork(initial)
    render(<App />)

    const account = screen.getByLabelText(label)
    const password = screen.getByLabelText('密码')
    fireEvent.change(account, { target: { value } })
    fireEvent.change(password, { target: { value: 'sufficiently-long-password' } })
    if (path === '/register') fireEvent.click(screen.getByRole('checkbox'))

    await finishInitial401(initial)

    expect(screen.getByLabelText(label)).toBe(account)
    expect(account).toHaveProperty('value', value)
    expect(screen.getByLabelText('密码')).toBe(password)
    expect(password).toHaveProperty('value', 'sufficiently-long-password')
    if (path === '/register') expect(screen.getByRole('checkbox')).toHaveProperty('checked', true)
  })

  it('已选择的 MFA 方法和验证码不被延迟首屏 401 清空', async () => {
    const initial = deferredResponse()
    const calls = installNetwork(initial)
    render(<App />)
    fireEvent.change(screen.getByLabelText('邮箱或用户名'), { target: { value: 'user@example.test' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-password' } })
    fireEvent.click(screen.getByRole('button', { name: /登录 · 进入星门/ }))
    fireEvent.click(await screen.findByRole('button', { name: /验证器 \(TOTP\)/ }))
    const code = screen.getByLabelText('一次性验证码')
    fireEvent.change(code, { target: { value: '123456' } })

    await finishInitial401(initial)

    expect(screen.getByLabelText('一次性验证码')).toBe(code)
    expect(code).toHaveProperty('value', '123456')
    expect(screen.queryByLabelText('邮箱或用户名')).toBeNull()
    expect(calls.filter((path) => path === '/api/v1/auth/login')).toHaveLength(1)
  })

  it('Owner 创建成功后，延迟首屏 401 保留完成提示和前往登录入口', async () => {
    replaceUrl('/bootstrap')
    const initial = deferredResponse()
    const calls = installNetwork(initial)
    render(<App />)
    fireEvent.change(screen.getByLabelText('管理员用户名'), { target: { value: 'new-owner' } })
    fireEvent.change(screen.getByLabelText('邮箱'), { target: { value: 'owner@example.test' } })
    fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-password' } })
    fireEvent.click(screen.getByRole('button', { name: '初始化并创建 Owner' }))
    expect(await screen.findByText('Owner 初始化成功，请使用新账号登录。')).toBeTruthy()
    const continueButton = screen.getByRole('button', { name: '前往登录' })

    await finishInitial401(initial)

    expect(screen.getByText('Owner 初始化成功，请使用新账号登录。')).toBeTruthy()
    expect(screen.getByRole('button', { name: '前往登录' })).toBe(continueButton)
    expect(screen.queryByLabelText('管理员用户名')).toBeNull()
    expect(calls.filter((path) => path === '/api/v1/admin/bootstrap')).toHaveLength(1)
  })
})

describe('OAuth 回调继续豁免页面代数重挂（#723、#731）', () => {
  it.each([
    ['/oauth/redirect?code=secret-code&state=xyz', '授权回调已收到'],
    ['/app/1/oauth/callback?code=secret-code&state=xyz', '授权完成，请返回应用'],
  ])('%s 清理 URL 后遇到真实跨标签登出，仍保留回调结果', async (path, title) => {
    replaceUrl(path)
    const originalHref = window.location.href
    const initial = deferredResponse()
    installNetwork(initial)
    render(<App />)
    const result = screen.getByText(title)
    expect(window.location.search).toBe('')
    await finishInitial401(initial)

    await act(async () => {
      window.dispatchEvent(new StorageEvent('storage', {
        key: AUTH_SYNC_KEY,
        newValue: JSON.stringify({ type: 'logout', nonce: 'explicit-remote-logout', occurredAt: Date.now() + 1_000 }),
      }))
    })

    expect(screen.getByText(title)).toBe(result)
    expect(screen.queryByText('授权回调无效')).toBeNull()
    expect(window.location.search).toBe('')
    if (path.startsWith('/app/')) {
      expect(screen.getByRole('link', { name: '打开应用继续' }).getAttribute('href')).toBe(originalHref)
    }
  })
})
