import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type {
  EmailPolicySetting,
  IssuerSettingResponse,
  OAuthProviderSummary,
  PasskeySetting,
  RegistrationSetting,
  SecurityLimitsSetting,
  SmtpSetting,
} from '../../api'
import { SettingsWorkspace } from './settings'
import { installCsrfCookie } from '../../test/csrf-cookie'

// 保存、密钥轮换、提供商启停都是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

/* #268：工作区的消息状态曾经每次渲染重建 flash，任一面板发消息都会让全部面板的
   加载 effect 重跑，把用户在别的面板里没保存的编辑冲回服务端值。这里从页面层
   验证：跨面板操作后各端点不重复 GET，草稿全部留存。 */

type CapturedRequest = { path: string; method: string; body?: Record<string, unknown> }

const PASSKEY: PasskeySetting = {
  enabled: true,
  rp_name: '辰星通行证',
  rp_id: 'auth.example.com',
  user_verification: 'preferred',
  authenticator_attachment: 'any',
  allow_insecure_origin: false,
  allowed_origins: ['https://auth.example.com'],
}

const EMAIL_POLICY: EmailPolicySetting = {
  whitelist_enabled: true,
  alias_restriction_enabled: true,
  allowed_domains: ['corp.example'],
  generation: 1,
}

const SMTP: SmtpSetting = {
  host: 'smtp.example.com',
  port: 465,
  username: 'noreply@example.com',
  from_address: '辰星认证中枢 <noreply@example.com>',
  ssl_enabled: true,
  force_auth_login: false,
  password_configured: true,
}

const SECURITY_LIMITS: SecurityLimitsSetting = {
  unauthenticated_source_qps: 30,
  authorization_code_ttl_seconds: 300,
  pending_request_ttl_seconds: 600,
  max_pending_requests_per_client: 20,
  max_pending_requests_global: 1000,
  auth_failure_window_seconds: 900,
  account_failure_limit: 10,
  ip_failure_limit: 30,
  totp_ticket_failure_limit: 5,
  external_login_state_ttl_seconds: 600,
  external_login_state_rate_window_seconds: 60,
  external_login_state_rate_limit: 30,
  external_login_state_max_pending: 10000,
}

const REGISTRATION: RegistrationSetting = {
  enabled: false,
  email_verification_required: false,
  invitation_code_required: false,
}

/* 公开注册面板挂载时会读 Issuer 运行时状态推导闸门；给一个就绪的 Issuer，
   让工作区测试不受闸门警告影响。 */
const ISSUER: IssuerSettingResponse = {
  persisted: null,
  loaded: { value: 'https://auth.example.com', generation: 1, updated_at: '2026-01-01T00:00:00Z' },
  phase: 'issuer_loaded',
}

const PROVIDER: OAuthProviderSummary = {
  id: 1,
  name: 'GitLab',
  slug: 'gitlab',
  status: 'active',
  client_secret_configured: true,
  authorization_endpoint: 'https://idp.example.com/oauth/authorize',
  token_endpoint: 'https://idp.example.com/oauth/token',
  userinfo_endpoint: 'https://idp.example.com/oauth/userinfo',
  client_id: 'client-abc',
  scopes: ['openid', 'profile', 'email'],
  subject_claim: 'sub',
  email_claim: 'email',
  name_claim: null,
  email_verified_claim: 'email_verified',
  client_auth_method: 'basic',
  pkce_enabled: true,
}

let requests: CapturedRequest[] = []

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function getCount(path: string): number {
  return requests.filter((request) => request.method === 'GET' && request.path === path).length
}

function loadedBody(path: string): unknown {
  if (path === '/api/v1/admin/settings/passkey') return PASSKEY
  if (path === '/api/v1/admin/settings/email-policy') return EMAIL_POLICY
  if (path === '/api/v1/admin/settings/smtp') return SMTP
  if (path === '/api/v1/admin/settings/security-limits') return SECURITY_LIMITS
  if (path === '/api/v1/admin/settings/registration') return REGISTRATION
  if (path === '/api/v1/admin/settings/issuer') return ISSUER
  if (path === '/api/v1/admin/oauth/providers') return [PROVIDER]
  return null
}

beforeEach(() => {
  requests = []
  vi.stubGlobal('confirm', () => true)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : undefined
    requests.push({ path, method, body: raw ? JSON.parse(raw) as Record<string, unknown> : undefined })
    if (method === 'GET') return Promise.resolve(jsonResponse(loadedBody(path)))
    if (path === '/api/v1/admin/keys/rotate') {
      return Promise.resolve(jsonResponse({ key_id: 'kid-2', published_key_count: 2 }))
    }
    if (path.startsWith('/api/v1/admin/settings/')) {
      // 保存接口回显完整设置对象：面板据此就地刷新，不需要再 GET 一次。
      const base = loadedBody(path) as Record<string, unknown>
      return Promise.resolve(jsonResponse({ ...base, ...(raw ? JSON.parse(raw) as Record<string, unknown> : {}) }))
    }
    return Promise.resolve(jsonResponse({ ok: true }))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const PERMISSIONS = ['manage_settings', 'manage_identity_providers', 'rotate_keys']

async function renderWorkspace(permissions: string[] = PERMISSIONS) {
  render(
    <SettingsWorkspace
      access={{
        data: { user_id: 7, username: 'star_owner', role: 'owner', permissions, status: 'active' },
        loading: false,
        error: '',
      }}
    />,
  )
  // 五个面板各自加载完成后才有表单可编辑。
  await screen.findByLabelText('SMTP 服务器地址')
  await screen.findByLabelText('服务显示名称')
  await screen.findByLabelText('未认证来源 QPS 上限')
  await screen.findByText('corp.example')
  await screen.findByText('GitLab')
}

function field(label: string): HTMLInputElement {
  return screen.getByLabelText(label) as HTMLInputElement
}

/** 在三个面板里各留一份未保存草稿，用来观察跨面板操作是否冲掉它们。 */
function fillDrafts() {
  fireEvent.change(field('SMTP 服务器地址'), { target: { value: 'draft.smtp.example' } })
  fireEvent.change(field('服务显示名称'), { target: { value: '草稿服务名' } })
  fireEvent.change(field('未认证来源 QPS 上限'), { target: { value: '77' } })
}

function expectDraftsIntact() {
  expect(field('SMTP 服务器地址').value).toBe('draft.smtp.example')
  expect(field('服务显示名称').value).toBe('草稿服务名')
  expect(field('未认证来源 QPS 上限').value).toBe('77')
}

function expectSingleLoadPerEndpoint() {
  expect(getCount('/api/v1/admin/settings/passkey')).toBe(1)
  expect(getCount('/api/v1/admin/settings/email-policy')).toBe(1)
  expect(getCount('/api/v1/admin/settings/smtp')).toBe(1)
  expect(getCount('/api/v1/admin/settings/security-limits')).toBe(1)
  expect(getCount('/api/v1/admin/settings/registration')).toBe(1)
}

function submitByButton(name: string) {
  const button = screen.getByRole('button', { name })
  fireEvent.submit(button.closest('form') as HTMLFormElement)
}

describe('SettingsWorkspace 加载 effect 与消息状态解耦', () => {
  it('挂载时每个端点只 GET 一次', async () => {
    await renderWorkspace()
    expectSingleLoadPerEndpoint()
    expect(getCount('/api/v1/admin/oauth/providers')).toBe(1)
  })

  it('某个面板保存成功后，其它面板不重新加载，草稿留存', async () => {
    await renderWorkspace()
    fillDrafts()

    submitByButton('保存邮箱域名白名单设置')
    // 消息条渲染即证明工作区已因消息状态重渲染过。
    await screen.findByText('邮箱域名白名单设置已保存。')

    expectSingleLoadPerEndpoint()
    expectDraftsIntact()
  })

  it('轮换签名密钥产生的成功消息不冲掉任何面板草稿', async () => {
    await renderWorkspace()
    fillDrafts()

    fireEvent.click(screen.getByRole('button', { name: '轮换签名密钥' }))
    await screen.findByText('签名密钥已轮换。')

    expectSingleLoadPerEndpoint()
    expectDraftsIntact()
  })

  it('警告类消息同样不触发重新加载', async () => {
    await renderWorkspace()
    fillDrafts()
    // 安全限流面板本地校验失败 → warning 消息，且不发 PUT。
    fireEvent.change(field('单账户失败次数上限'), { target: { value: '0' } })
    submitByButton('保存安全限流配置')

    await screen.findByText('「单账户失败次数上限」必须填写大于 0 的整数。')
    expect(requests.some((request) => request.method === 'PUT')).toBe(false)
    expectSingleLoadPerEndpoint()
    expect(field('SMTP 服务器地址').value).toBe('draft.smtp.example')
    expect(field('服务显示名称').value).toBe('草稿服务名')
  })

  it('OAuth 提供商启停只刷新自己的列表，不动其它面板', async () => {
    await renderWorkspace()
    fillDrafts()

    fireEvent.click(screen.getByRole('button', { name: '禁用' }))
    await waitFor(() => expect(getCount('/api/v1/admin/oauth/providers')).toBe(2))

    expectSingleLoadPerEndpoint()
    expectDraftsIntact()
  })

  it('保存成功的面板自身会用服务端返回值刷新，不依赖重新 GET', async () => {
    await renderWorkspace()
    fireEvent.change(field('SMTP 服务器地址'), { target: { value: 'new.smtp.example' } })
    submitByButton('保存 SMTP 设置')

    await screen.findByText('SMTP 设置已保存。')
    expect(field('SMTP 服务器地址').value).toBe('new.smtp.example')
    expect(getCount('/api/v1/admin/settings/smtp')).toBe(1)
    const saved = requests.find((request) => request.method === 'PUT' && request.path === '/api/v1/admin/settings/smtp')
    expect(saved?.body).toMatchObject({ host: 'new.smtp.example', password_action: 'keep' })
    expect(saved?.body).not.toHaveProperty('password')
  })
})

describe('SettingsWorkspace 权限退化', () => {
  it('缺少 manage_identity_providers 时不加载提供商列表', async () => {
    render(
      <SettingsWorkspace
        access={{
          data: { user_id: 7, username: 'star_owner', role: 'admin', permissions: ['manage_settings'], status: 'active' },
          loading: false,
          error: '',
        }}
      />,
    )
    await screen.findByLabelText('SMTP 服务器地址')
    expect(screen.getByText('需要 `manage_identity_providers` 权限后才能管理外部身份提供商。')).toBeTruthy()
    expect(getCount('/api/v1/admin/oauth/providers')).toBe(0)
  })
})
