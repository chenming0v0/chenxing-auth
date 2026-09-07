import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { OAuthIdentitiesPage } from './oauth-identities'

vi.mock('../../components/shells', () => ({
  ConsoleLayout: ({ children }: { children: ReactNode }) => <>{children}</>,
}))

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const IDENTITY = {
  provider: 'github',
  provider_name: 'GitHub',
  account_name: 'octocat',
  email: 'octocat@example.com',
  avatar_url: 'https://avatars.example.test/octocat.png',
  subject_hint: 'gh-subject-42',
  linked_at: '2026-09-01T08:00:00Z',
  last_synced_at: '2026-09-05T08:00:00Z',
  extensions: [{
    namespace: 'cltermux',
    version: '1',
    fetched_at: '2026-09-05T08:00:00Z',
    fields: [
      { key: 'uid', label: 'CLtermux UID', type: 'text', value: 'cltermux:123' },
      { key: 'remaining_days', label: '剩余订阅', type: 'duration_days', value: 42 },
      { key: 'subscribed', label: '是否订阅', type: 'boolean', value: true },
      { key: 'raw', label: '未知字段', type: 'vendor_blob', value: { unsafe: '<script>' } },
    ],
  }],
}

let responseBody: unknown = { items: [IDENTITY] }
let failNext = false
let requests: string[] = []

beforeEach(() => {
  window.history.replaceState({}, '', '/console/account/oauth-identities')
  responseBody = { items: [IDENTITY] }
  failNext = false
  requests = []
  vi.stubGlobal('fetch', vi.fn((path: string) => {
    requests.push(path)
    if (failNext) {
      failNext = false
      return Promise.reject(new Error('network down'))
    }
    return Promise.resolve(jsonResponse(responseBody))
  }))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('OAuthIdentitiesPage (#707)', () => {
  it('renders standard identity data and typed provider extensions without executing unknown fields', async () => {
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByRole('heading', { name: 'OAuth 登录账号' })).toBeTruthy()
    expect(screen.getByText('GitHub')).toBeTruthy()
    expect(screen.getByText('octocat@example.com')).toBeTruthy()
    expect(screen.getByText('CLtermux UID')).toBeTruthy()
    expect(screen.getByText('cltermux:123')).toBeTruthy()
    expect(screen.getByText('42 天')).toBeTruthy()
    expect(screen.getByText('是')).toBeTruthy()
    expect(screen.getByText('该字段类型暂不支持展示')).toBeTruthy()
    expect(screen.queryByText('<script>')).toBeNull()
    expect(screen.queryByText('gh-subject-42')).toBeNull()
    expect(screen.getByText(/gh.*••••.*42/)).toBeTruthy()
  })

  it('shows an empty state with a binding entry when no identity is linked', async () => {
    responseBody = { items: [] }
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByText('暂无 OAuth 登录账号')).toBeTruthy()
    expect(screen.getByRole('link', { name: '前往账户绑定' }).getAttribute('href')).toBe('/console/profile')
  })

  it('refreshes one provider and updates its extension values', async () => {
    render(<OAuthIdentitiesPage />)
    await screen.findByText('GitHub')
    responseBody = { items: [{ ...IDENTITY, extensions: [{ ...IDENTITY.extensions[0], fields: [{ ...IDENTITY.extensions[0].fields[1], value: 12 }] }] }] }

    fireEvent.click(screen.getByRole('button', { name: '刷新 GitHub 数据' }))
    await waitFor(() => expect(screen.getByText('12 天')).toBeTruthy())
    expect(requests).toHaveLength(2)
    expect(screen.getByText('GitHub 数据已刷新。')).toBeTruthy()
  })

  it('keeps the previous snapshot and marks sync failure when refresh fails', async () => {
    render(<OAuthIdentitiesPage />)
    await screen.findByText('42 天')
    failNext = true

    fireEvent.click(screen.getByRole('button', { name: '刷新 GitHub 数据' }))
    await waitFor(() => expect(screen.getByText('同步失败')).toBeTruthy())
    expect(screen.getByText('42 天')).toBeTruthy()
    expect(screen.getByText(/保留上一次成功数据/)).toBeTruthy()
  })

  it('rejects malformed typed values through the API response guard', async () => {
    responseBody = { items: [{ ...IDENTITY, extensions: [{ ...IDENTITY.extensions[0], fields: [{ ...IDENTITY.extensions[0].fields[1], value: '42' }] }] }] }
    render(<OAuthIdentitiesPage />)

    expect(await screen.findByText(/无法加载 OAuth 登录账号/)).toBeTruthy()
    expect(screen.queryByText('GitHub')).toBeNull()
  })

  it('provides an accessible full-value control for long extension values', async () => {
    const longValue = 'device-' + 'x'.repeat(140)
    responseBody = { items: [{ ...IDENTITY, extensions: [{ ...IDENTITY.extensions[0], fields: [{ key: 'device', label: '设备状态', type: 'text', value: longValue }] }] }] }
    render(<OAuthIdentitiesPage />)

    await screen.findByText('设备状态')
    const button = screen.getByRole('button', { name: '查看完整值' })
    expect(button.getAttribute('aria-controls')).toBeTruthy()
    expect(button.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(button)
    expect(button.getAttribute('aria-expanded')).toBe('true')
    expect(screen.getByText(`完整值：${longValue}`)).toBeTruthy()
  })
})
