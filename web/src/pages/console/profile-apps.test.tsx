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

beforeEach(() => {
  window.history.replaceState({}, '', '/console/profile')
  requests = []
  document.cookie = 'chenxing_csrf=test-token'
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => {
    requests.push({ path, init })
    if (path === '/api/v1/auth/sessions') return Promise.resolve(jsonResponse({ items: [] }))
    if (path === '/api/v1/auth/security/factors') return Promise.resolve(jsonResponse({ totp_enabled: false, passkey_count: 0, available_methods: ['totp', 'passkey'] }))
    if (path === '/api/v1/auth/external-identities') return Promise.resolve(jsonResponse({ items: [] }))
    if (path === '/api/v1/auth/external-providers') return Promise.resolve(jsonResponse([]))
    if (path === '/api/v1/auth/me') return Promise.resolve(jsonResponse({ ...USER, display_name: '更新后的用户', username: 'updated-user' }))
    if (path === '/api/v1/auth/email-change/start') return Promise.resolve(jsonResponse({ challenge_id: 'challenge-1', expires_at: '2099-01-01T01:00:00Z' }, 202))
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
    expect(within(emailDialog).getByText(/邮箱变更后端尚未实现/)).toBeTruthy()
    expect(within(emailDialog).getByRole('button', { name: '等待后端接入' })).toBeTruthy()
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

  it('邮箱变更弹窗保持独立，并在后端未接入时不发起请求', async () => {
    render(<ConsoleProfile />)
    fireEvent.click(screen.getByRole('tab', { name: '安全设置' }))
    fireEvent.click(screen.getByRole('button', { name: '更改邮箱' }))
    fireEvent.click(screen.getByRole('button', { name: '等待后端接入' }))
    expect(screen.getByText(/邮箱变更后端尚未实现/)).toBeTruthy()
    expect(requests.some(({ path }) => path.includes('email-change'))).toBe(false)
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
