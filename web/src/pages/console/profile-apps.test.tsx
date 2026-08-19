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

  it('修改密码只在独立弹窗中展示，不在安全设置项内展开', async () => {
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
