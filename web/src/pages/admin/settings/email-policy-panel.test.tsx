import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { EmailPolicySetting } from '../../../api'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { EmailPolicyPanel } from './email-policy-panel'

// 保存走 PUT /api/v1/admin/settings/email-policy 的 apiFetch，需要 CSRF cookie 才能发出。
installCsrfCookie()

type CapturedRequest = { method: string; body?: Record<string, unknown> }

let requests: CapturedRequest[] = []
let confirmCalls = 0
let confirmMessage = ''
let confirmResult = true
let policy: EmailPolicySetting

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  requests = []
  confirmCalls = 0
  confirmMessage = ''
  confirmResult = true
  policy = {
    whitelist_enabled: true,
    alias_restriction_enabled: true,
    allowed_domains: ['corp.example'],
  }
  vi.stubGlobal('confirm', (message: string) => {
    confirmCalls += 1
    confirmMessage = message
    return confirmResult
  })
  vi.stubGlobal('fetch', (_path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : undefined
    requests.push({ method, body: raw ? JSON.parse(raw) as Record<string, unknown> : undefined })
    if (method === 'GET') return Promise.resolve(jsonResponse(policy))
    return Promise.resolve(jsonResponse(raw ? JSON.parse(raw) : policy))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

async function renderPanel() {
  render(<EmailPolicyPanel onMessage={vi.fn()} onDirtyChange={() => {}} />)
  await screen.findByText('corp.example')
}

function save() {
  const button = screen.getByRole('button', { name: '保存邮箱域名白名单设置' })
  fireEvent.submit(button.closest('form') as HTMLFormElement)
}

describe('EmailPolicyPanel 域名输入', () => {
  it('按后端规则规范化并拒绝邮箱地址', async () => {
    await renderPanel()
    const input = screen.getByLabelText('输入要添加的邮箱域名')
    fireEvent.change(input, { target: { value: '  NEW.EXAMPLE.COM  ' } })
    fireEvent.click(screen.getByRole('button', { name: '添加' }))
    expect(screen.getByText('new.example.com')).toBeTruthy()

    fireEvent.change(input, { target: { value: 'user@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: '添加' }))
    expect(screen.getByText('这里只填写域名，例如 example.com，不要填写邮箱地址。')).toBeTruthy()
    expect(requests.some((request) => request.method === 'PUT')).toBe(false)
  })

  it('关闭白名单并清空原有有效白名单时要求确认', async () => {
    confirmResult = false
    await renderPanel()
    fireEvent.click(screen.getByRole('switch', { name: '启用邮箱域名白名单' }))
    fireEvent.click(screen.getByRole('button', { name: '移除' }))
    save()

    expect(confirmCalls).toBe(1)
    expect(confirmMessage).toContain('不再按允许域名限制')
    expect(requests.some((request) => request.method === 'PUT')).toBe(false)
  })

  it('关闭白名单并保留原有列表时也要求确认', async () => {
    await renderPanel()
    fireEvent.click(screen.getByRole('switch', { name: '启用邮箱域名白名单' }))
    save()

    expect(confirmCalls).toBe(1)
    expect(confirmMessage).toContain('当前允许域名列表将被忽略')
    await waitFor(() =>
      expect(requests[requests.length - 1]?.body).toMatchObject({
        whitelist_enabled: false,
        allowed_domains: ['corp.example'],
      }),
    )
  })

  it('白名单原本关闭时清空被忽略的列表不要求确认', async () => {
    policy.whitelist_enabled = false
    await renderPanel()
    fireEvent.click(screen.getByRole('button', { name: '移除' }))
    save()

    expect(confirmCalls).toBe(0)
    await waitFor(() => expect(requests.some((request) => request.method === 'PUT')).toBe(true))
  })

  it('白名单启用但列表为空时显示原因并阻止保存', async () => {
    policy.allowed_domains = []
    const onMessage = vi.fn()
    render(<EmailPolicyPanel onMessage={onMessage} onDirtyChange={() => {}} />)
    await screen.findByText('白名单已启用但允许域名列表为空，无法保存。请至少添加一个域名，或关闭白名单。')
    save()

    expect(onMessage).toHaveBeenCalledWith(
      '白名单已启用但允许域名列表为空，无法保存。请至少添加一个域名，或关闭白名单。',
      'warning',
    )
    expect(requests.some((request) => request.method === 'PUT')).toBe(false)
  })
})
