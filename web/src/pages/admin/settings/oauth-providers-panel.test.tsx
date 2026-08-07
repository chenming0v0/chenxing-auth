import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent } from '@testing-library/react'
import type { OAuthProviderSummary } from '../../../api'
import { OAuthProvidersPanel } from './oauth-providers-panel'

type CapturedRequest = { path: string; method?: string; body: Record<string, unknown> }

let requests: CapturedRequest[] = []
let providers: OAuthProviderSummary[]

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

const baseProvider = {
  authorization_endpoint: 'https://idp.example.com/oauth/authorize',
  token_endpoint: 'https://idp.example.com/oauth/token',
  userinfo_endpoint: 'https://idp.example.com/oauth/userinfo',
  client_id: 'client-abc',
  scopes: ['openid', 'profile', 'email'] as string[],
  subject_claim: 'sub',
  email_claim: 'email',
  name_claim: null,
  email_verified_claim: null,
  client_auth_method: 'basic' as const,
}

const CONFIGURED: OAuthProviderSummary = {
  ...baseProvider,
  id: 1,
  name: 'GitLab',
  slug: 'gitlab',
  status: 'active',
  client_secret_configured: true,
}

const UNCONFIGURED: OAuthProviderSummary = {
  ...baseProvider,
  id: 2,
  name: 'Gitea',
  slug: 'gitea',
  status: 'disabled',
  client_secret_configured: false,
}

beforeEach(() => {
  requests = []
  providers = [CONFIGURED, UNCONFIGURED]
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, method, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(jsonResponse(method === 'GET' ? providers : { ok: true }))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderPanel() {
  const onMessage = vi.fn()
  render(<OAuthProvidersPanel onMessage={onMessage} />)
  return onMessage
}

async function openEditRow(name: string) {
  const rows = screen.getAllByRole('row').filter((row) => row.textContent?.includes(name))
  fireEvent.click(rows[0].querySelector('button[class*="chenxing-link"]') as HTMLButtonElement)
  await screen.findByText('编辑 OAuth 提供商')
}

function save() {
  const button = screen.getByRole('button', { name: '保存' })
  fireEvent.submit(button.closest('form') as HTMLFormElement)
}

describe('OAuthProvidersPanel Client Secret 状态展示', () => {
  it('列表按 client_secret_configured 显示已配置 / 未配置徽标', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    expect(screen.getByText('已配置')).toBeTruthy()
    expect(screen.getByText('未配置')).toBeTruthy()
  })

  it('编辑已配置提供商时不回显密钥，且提示留空保持 / 输入替换', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    await openEditRow('GitLab')
    const input = screen.getByLabelText('Client Secret') as HTMLInputElement
    expect(input.value).toBe('')
    expect(input.required).toBe(false)
    expect(screen.getByText('已配置 Client Secret：留空保持不变，输入新值替换。保存后不会回显明文。')).toBeTruthy()
  })

  it('编辑未配置提供商时给出明确警告并标记必填', async () => {
    renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    const input = screen.getByLabelText('Client Secret *') as HTMLInputElement
    expect(input.required).toBe(true)
    expect(screen.getByText('尚未配置 Client Secret，用户通过该提供商登录将失败。请输入密钥后保存。')).toBeTruthy()
  })
})

describe('OAuthProvidersPanel Client Secret 提交语义', () => {
  it('已配置提供商留空密钥提交时不发送 client_secret 字段（保持原值）', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    await openEditRow('GitLab')
    save()
    const put = requests.find((r) => r.method === 'PUT')
    expect(put).toBeTruthy()
    expect(put?.body.client_secret).toBeUndefined()
  })

  it('未配置提供商不填密钥时阻止提交并提示', async () => {
    const onMessage = renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    save()
    expect(requests.some((r) => r.method === 'PUT')).toBe(false)
    expect(onMessage).toHaveBeenCalledWith('该提供商尚未配置 Client Secret，无法保存。请输入密钥。', 'warning')
  })

  it('未配置提供商填入新密钥后提交替换', async () => {
    renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    fireEvent.change(screen.getByLabelText('Client Secret *'), { target: { value: 'new-secret' } })
    save()
    const put = requests.find((r) => r.method === 'PUT')
    expect(put?.body.client_secret).toBe('new-secret')
  })

  it('创建提供商时密钥为空同样被阻止', async () => {
    const onMessage = renderPanel()
    await screen.findByText('GitLab')
    fireEvent.click(screen.getByRole('button', { name: '添加 OAuth 提供商' }))
    save()
    expect(requests.some((r) => r.method === 'POST' && r.path.endsWith('/providers'))).toBe(false)
    expect(onMessage).toHaveBeenCalledWith('创建提供商时必须填写 Client Secret。', 'warning')
  })
})
