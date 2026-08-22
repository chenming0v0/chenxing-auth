import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { ConsoleProfile } from './profile-apps'

const USER = {
  id: 1,
  username: 'chenxing',
  email: 'user@chenxing.star',
  display_name: '辰星用户',
  status: 'active',
  role: 'user',
  current_session_expires_at: '2099-01-01T00:00:00Z',
  avatar_updated_at: null,
}

vi.mock('../../auth-state', () => ({
  useAuth: () => ({
    user: USER,
    clear: vi.fn(),
    refresh: vi.fn(),
  }),
}))

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

let requests: Array<{ path: string; init?: RequestInit }> = []
let emailChallengeSequence = 0

beforeEach(() => {
  window.history.replaceState({}, '', '/console/profile')
  requests = []
  emailChallengeSequence = 0
  document.cookie = 'chenxing_csrf=test-token'
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    requests.push({ path, init })
    if (path === '/api/v1/auth/sessions') return Promise.resolve(jsonResponse({ items: [] }))
    if (path === '/api/v1/auth/security/factors') return Promise.resolve(jsonResponse({ totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }))
    if (path === '/api/v1/auth/external-identities') return Promise.resolve(jsonResponse({ items: [] }))
    if (path === '/api/v1/auth/external-providers') return Promise.resolve(jsonResponse([]))
    if (path === '/api/v1/auth/me') return Promise.resolve(jsonResponse({ ...USER, display_name: '更新后的用户', username: 'updated-user' }))
    if (path === '/api/v1/auth/email-change/start') return Promise.resolve(jsonResponse({ challenge_id: `challenge-${++emailChallengeSequence}`, expires_at: '2099-01-01T01:00:00Z' }, 202))
    if (path === '/api/v1/auth/email-change/confirm') return Promise.resolve(jsonResponse(null, 204))
    return Promise.reject(new Error(`unexpected request: ${path}`))
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ConsoleProfile 账户设置布局', () => {
  it('账户资料和邮箱地址使用同级的独立编辑弹窗', async () => {
    render(<ConsoleProfile />)

    expect(await screen.findByRole('heading', { name: '账户管理' })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: '基本资料' })).toBeNull()

    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    expect(screen.queryByLabelText('显示名称')).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '修改账户资料' }))
    const profileDialog = screen.getByRole('dialog', { name: '修改账户资料' })
    expect(profileDialog.parentElement?.className).toContain('z-[var(--chenxing-z-overlay)]')
    expect(within(profileDialog).getByLabelText('显示名称')).toHaveProperty('value', '辰星用户')
    expect(within(profileDialog).getByLabelText('用户名')).toHaveProperty('value', 'chenxing')
    expect(within(profileDialog).queryByText(/邮箱/)).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    const emailDialog = screen.getByRole('dialog', { name: '更改邮箱' })
    expect(emailDialog.parentElement?.className).toContain('z-[var(--chenxing-z-overlay)]')
    expect(within(emailDialog).getByText('user@chenxing.star')).toBeTruthy()
    expect(within(emailDialog).getByLabelText('新邮箱地址')).toBeTruthy()
    expect(within(emailDialog).getByLabelText('当前密码')).toBeTruthy()
    expect(within(emailDialog).getByText(/验证码将发送到新邮箱/)).toBeTruthy()
    expect(within(emailDialog).getByRole('button', { name: '发送验证码' })).toBeTruthy()
  })

  it('用户名修改提交真实 PATCH，并在成功后进入下一步', async () => {
    render(<ConsoleProfile />)
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '修改账户资料' }))
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '更新后的用户' } })
    fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'updated-user' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '保存账户资料' }))

    await waitFor(() => expect(requests.some(({ path }) => path === '/api/v1/auth/me')).toBe(true))
    const request = requests.find(({ path }) => path === '/api/v1/auth/me')
    expect(JSON.parse(String(request?.init?.body))).toMatchObject({
      display_name: '更新后的用户',
      username: 'updated-user',
      current_password: 'correct-password',
    })
    expect(screen.queryByText(/等待接口接入|Issue #558/)).toBeNull()
  })

  it('邮箱变更先发送验证码，再提交确认码', async () => {
    render(<ConsoleProfile />)
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'new@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '发送验证码' }))
    await waitFor(() => expect(screen.getByLabelText('邮箱验证码')).toBeTruthy())
    expect(requests.some(({ path }) => path === '/api/v1/auth/email-change/start')).toBe(true)
    fireEvent.change(screen.getByLabelText('邮箱验证码'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: '确认变更' }))
    await waitFor(() => expect(requests.some(({ path }) => path === '/api/v1/auth/email-change/confirm')).toBe(true))
  })

  it('关闭并重新打开邮箱编辑器会重置旧 challenge 和验证码', async () => {
    render(<ConsoleProfile />)
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'first@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '发送验证码' }))
    await waitFor(() => expect(screen.getByLabelText('邮箱验证码')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('邮箱验证码'), { target: { value: '123456' } })

    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    expect(screen.queryByRole('dialog', { name: '更改邮箱' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    expect(screen.getByLabelText('新邮箱地址')).toHaveProperty('value', '')
    expect(screen.getByLabelText('当前密码')).toHaveProperty('value', '')
    expect(screen.queryByLabelText('邮箱验证码')).toBeNull()
    expect(screen.queryByText('验证码已发送到新邮箱。')).toBeNull()

    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'second@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '发送验证码' }))
    await waitFor(() => expect(screen.getByLabelText('邮箱验证码')).toBeTruthy())
    fireEvent.change(screen.getByLabelText('邮箱验证码'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: '确认变更' }))

    await waitFor(() => expect(requests.filter(({ path }) => path === '/api/v1/auth/email-change/confirm')).toHaveLength(1))
    const confirmRequest = requests.find(({ path }) => path === '/api/v1/auth/email-change/confirm')
    expect(JSON.parse(String(confirmRequest?.init?.body))).toEqual({ challenge_id: 'challenge-2', code: '654321' })
  })

  it('关闭并重新打开时忽略仍在途的旧 start 响应', async () => {
    const startResponses: Array<(value: Response) => void> = []
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      requests.push({ path, init })
      if (path === '/api/v1/auth/sessions') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/v1/auth/security/factors') return Promise.resolve(jsonResponse({ totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }))
      if (path === '/api/v1/auth/external-identities') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/v1/auth/external-providers') return Promise.resolve(jsonResponse([]))
      if (path === '/api/v1/auth/email-change/start') return new Promise<Response>((resolve) => startResponses.push(resolve))
      return Promise.reject(new Error(`unexpected request: ${path}`))
    }))

    render(<ConsoleProfile />)
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'old@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '发送验证码' }))
    await waitFor(() => expect(startResponses).toHaveLength(1))

    fireEvent.click(screen.getByRole('button', { name: '关闭' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    expect(screen.getByRole('button', { name: '发送中…' })).toHaveProperty('disabled', true)
    expect(screen.queryByLabelText('邮箱验证码')).toBeNull()

    startResponses.shift()?.(jsonResponse({ challenge_id: 'stale-challenge', expires_at: '2099-01-01T01:00:00Z' }, 202))
    await waitFor(() => expect(screen.getByRole('button', { name: '发送验证码' })).toBeTruthy())
    expect(screen.queryByLabelText('邮箱验证码')).toBeNull()
    expect(screen.queryByText('验证码已发送到新邮箱。')).toBeNull()

    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'new@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: '发送验证码' }))
    await waitFor(() => expect(startResponses).toHaveLength(1))
    startResponses.shift()?.(jsonResponse({ challenge_id: 'new-challenge', expires_at: '2099-01-01T01:00:00Z' }, 202))
    await waitFor(() => expect(screen.getByLabelText('邮箱验证码')).toBeTruthy())
    expect(screen.getByRole('button', { name: '确认变更' })).toBeTruthy()
  })

  it('ignores an older session reload after a newer revoke reload', async () => {
    const deferred: Array<(value: Response) => void> = []
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      requests.push({ path, init })
      if (path === '/api/v1/auth/sessions') return new Promise<Response>((resolve) => deferred.push(resolve))
      return Promise.reject(new Error(`unexpected request: ${path}`))
    }))
    render(<ConsoleProfile />)
    deferred.shift()?.(jsonResponse({ items: [{ id: 1, current: false, created_at: '2099-01-01', expires_at: '2099-01-02' }] }))
    await screen.findByText('其他会话')
    expect(deferred).toHaveLength(0)
  })

  it('非当前会话撤销失败后可以再次尝试', async () => {
    const session = { id: 2, current: false, created_at: '2099-01-01', expires_at: '2099-01-02' }
    let deleteAttempts = 0
    let sessionLoads = 0
    vi.stubGlobal('confirm', () => true)
    vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
      requests.push({ path, init })
      if (path === '/api/v1/auth/sessions' && init?.method === undefined) {
        sessionLoads += 1
        return Promise.resolve(jsonResponse({ items: sessionLoads === 1 ? [session] : [] }))
      }
      if (path === '/api/v1/auth/sessions/2' && init?.method === 'DELETE') {
        deleteAttempts += 1
        return deleteAttempts === 1
          ? Promise.reject(new Error('temporary revoke failure'))
          : Promise.resolve(jsonResponse(null, 204))
      }
      return Promise.reject(new Error(`unexpected request: ${path}`))
    }))

    render(<ConsoleProfile />)
    const revokeButton = await screen.findByRole('button', { name: '撤销' })
    fireEvent.click(revokeButton)

    await waitFor(() => expect(screen.getByText('网络连接不可用，请稍后重试。')).toBeTruthy())
    expect((screen.getByRole('button', { name: '撤销' }) as HTMLButtonElement).disabled).toBe(false)

    fireEvent.click(screen.getByRole('button', { name: '撤销' }))
    await waitFor(() => expect(deleteAttempts).toBe(2))
    await waitFor(() => expect(screen.queryByRole('button', { name: '撤销' })).toBeNull())
  })

  it('密码修改使用独立弹窗', async () => {
    render(<ConsoleProfile />)

    await screen.findByRole('heading', { name: '账户管理' })
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))

    expect(screen.queryByLabelText('新密码')).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }))

    const passwordDialog = screen.getByRole('dialog', { name: '修改密码' })
    expect(passwordDialog.parentElement?.className).toContain('z-[var(--chenxing-z-overlay)]')
    expect(within(passwordDialog).getByLabelText('当前密码')).toBeTruthy()
    expect(within(passwordDialog).getByLabelText('新密码')).toBeTruthy()
    expect(within(passwordDialog).getByLabelText('确认新密码')).toBeTruthy()
  })
})

describe('ConsoleProfile 提交互斥（#586）', () => {
  function hangMutations() {
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      requests.push({ path, init })
      if (path === '/api/v1/auth/sessions') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/v1/auth/security/factors') return Promise.resolve(jsonResponse({ totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }))
      if (path === '/api/v1/auth/external-identities') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/v1/auth/external-providers') return Promise.resolve(jsonResponse([]))
      if (path === '/api/v1/auth/me' && init?.method === 'PATCH') return new Promise<Response>(() => {})
      if (path === '/api/v1/auth/password') return new Promise<Response>(() => {})
      if (path === '/api/v1/auth/email-change/start') return new Promise<Response>(() => {})
      return Promise.reject(new Error(`unexpected request: ${path}`))
    })
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }

  it('资料保存在 busy 尚未重渲染时重复提交只发出一个 PATCH', async () => {
    hangMutations()
    render(<ConsoleProfile />)
    await screen.findByRole('heading', { name: '账户管理' })
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '修改账户资料' }))
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '更新后的用户' } })

    const form = screen.getByRole('button', { name: '保存账户资料' }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => {
      expect(requests.filter(({ path, init }) => path === '/api/v1/auth/me' && init?.method === 'PATCH')).toHaveLength(1)
    })
    expect(requests.filter(({ path, init }) => path === '/api/v1/auth/me' && init?.method === 'PATCH')).toHaveLength(1)
  })

  it('资料保存期间关闭按钮、遮罩和 Escape 都不能关闭弹窗', async () => {
    hangMutations()
    render(<ConsoleProfile />)
    await screen.findByRole('heading', { name: '账户管理' })
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '修改账户资料' }))
    fireEvent.change(screen.getByLabelText('显示名称'), { target: { value: '更新后的用户' } })

    fireEvent.submit(screen.getByRole('button', { name: '保存账户资料' }).closest('form') as HTMLFormElement)
    await screen.findByRole('button', { name: '保存中…' })

    const dialog = screen.getByRole('dialog', { name: '修改账户资料' })
    const overlay = dialog.parentElement
    const close = within(dialog).getByRole('button', { name: '关闭' }) as HTMLButtonElement
    expect(close.disabled).toBe(true)
    if (!overlay) throw new Error('Profile editor overlay is missing')

    fireEvent.click(close)
    fireEvent.mouseDown(overlay)
    fireEvent.keyDown(document, { key: 'Escape' })

    expect(screen.getByRole('dialog', { name: '修改账户资料' })).toBe(dialog)
  })

  it('密码修改在 busy 尚未重渲染时重复提交只发出一个 POST', async () => {
    hangMutations()
    render(<ConsoleProfile />)
    await screen.findByRole('heading', { name: '账户管理' })
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '修改密码' }))
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'old-password-long' } })
    fireEvent.change(screen.getByLabelText('新密码'), { target: { value: 'new-password-long' } })
    fireEvent.change(screen.getByLabelText('确认新密码'), { target: { value: 'new-password-long' } })

    const form = screen.getByRole('button', { name: '确认修改' }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => {
      expect(requests.filter(({ path }) => path === '/api/v1/auth/password')).toHaveLength(1)
    })
    expect(requests.filter(({ path }) => path === '/api/v1/auth/password')).toHaveLength(1)
  })

  it('邮箱变更在 busy 尚未重渲染时重复提交只发出一个 start 请求', async () => {
    hangMutations()
    render(<ConsoleProfile />)
    await screen.findByRole('heading', { name: '账户管理' })
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    fireEvent.change(screen.getByLabelText('新邮箱地址'), { target: { value: 'new@example.com' } })
    fireEvent.change(screen.getByLabelText('当前密码'), { target: { value: 'correct-password' } })

    const form = screen.getByRole('button', { name: '发送验证码' }).closest('form') as HTMLFormElement
    fireEvent.submit(form)
    fireEvent.submit(form)

    await waitFor(() => {
      expect(requests.filter(({ path }) => path === '/api/v1/auth/email-change/start')).toHaveLength(1)
    })
    expect(requests.filter(({ path }) => path === '/api/v1/auth/email-change/start')).toHaveLength(1)
  })
})
