import { expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { OAuthProviderSummary } from '../../../api'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { OAuthProvidersPanel } from './oauth-providers-panel'

// 提供商的增删改启停都是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

type CapturedRequest = { path: string; method?: string; body: Record<string, unknown> }

export let requests: CapturedRequest[] = []
export let providers: OAuthProviderSummary[]
export function replaceProviders(next: OAuthProviderSummary[]) { providers = next }
/** slug -> 该 slug 的 enable 还要失败几次；用来构造「落库成功、状态切换失败」的部分成功 */
export let enableFailures: Map<string, number>

export function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

export const baseProvider = {
  authorization_endpoint: 'https://idp.example.com/oauth/authorize',
  token_endpoint: 'https://idp.example.com/oauth/token',
  userinfo_endpoint: 'https://idp.example.com/oauth/userinfo',
  client_id: 'client-abc',
  scopes: ['openid', 'profile', 'email'] as string[],
  subject_claim: 'sub',
  email_claim: 'email',
  name_claim: null,
  email_verified_claim: 'email_verified',
  client_auth_method: 'basic' as const,
  pkce_enabled: true,
}

export const CONFIGURED: OAuthProviderSummary = {
  ...baseProvider,
  id: 1,
  name: 'GitLab',
  slug: 'gitlab',
  status: 'active',
  client_secret_configured: true,
}

export const UNCONFIGURED: OAuthProviderSummary = {
  ...baseProvider,
  id: 2,
  name: 'Gitea',
  slug: 'gitea',
  status: 'disabled',
  client_secret_configured: false,
}

export const PROVIDERS_PATH = '/api/v1/admin/oauth/providers'

export function setStatus(slug: string, status: 'active' | 'disabled') {
  providers = providers.map((item) => (item.slug === slug ? { ...item, status } : item))
}

/**
 * 有状态的假后端：创建落库后 provider 默认停用（与 openapi 的 201 语义一致），
 * enable / disable 单独改状态。只有这样才能区分「创建失败」和「创建成功但启用失败」。
 */
export function handle(path: string, method: string, body: Record<string, unknown>): Response {
  const endpoint = path.slice(PROVIDERS_PATH.length)
  if (method === 'GET') return jsonResponse(providers)
  if (method === 'POST' && endpoint === '') {
    const slug = String(body.slug)
    const created: OAuthProviderSummary = {
      ...baseProvider,
      id: providers.length + 100,
      name: String(body.name),
      slug,
      status: 'disabled',
      client_secret_configured: true,
    }
    if (providers.some((item) => item.slug === slug)) {
      return jsonResponse({ code: 'oauth_provider_slug_conflict' }, 409)
    }
    providers = [...providers, created]
    return jsonResponse(created, 201)
  }
  const action = endpoint.endsWith('/enable') ? 'enable' : endpoint.endsWith('/disable') ? 'disable' : null
  const slug = decodeURIComponent(endpoint.replace(/^\//, '').replace(/\/(enable|disable)$/, ''))
  if (action === 'enable') {
    const remaining = enableFailures.get(slug) ?? 0
    if (remaining > 0) {
      enableFailures.set(slug, remaining - 1)
      return jsonResponse({ code: 'invalid_oauth_provider' }, 400)
    }
    setStatus(slug, 'active')
    return jsonResponse({ ok: true })
  }
  if (action === 'disable') {
    setStatus(slug, 'disabled')
    return jsonResponse({ ok: true })
  }
  return jsonResponse({ ok: true })
}

beforeEach(() => {
  requests = []
  providers = [CONFIGURED, UNCONFIGURED]
  enableFailures = new Map()
  // 行内启用 / 禁用带 confirm；jsdom 的默认实现会抛 Not implemented。
  vi.stubGlobal('confirm', () => true)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    const body = JSON.parse(raw) as Record<string, unknown>
    requests.push({ path, method, body })
    return Promise.resolve(handle(path, method, body))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

export function renderPanel() {
  const onMessage = vi.fn()
  render(<OAuthProvidersPanel onMessage={onMessage} onDirtyChange={() => {}} />)
  return onMessage
}

export async function openEditRow(name: string) {
  const rows = screen.getAllByRole('row').filter((row) => row.textContent?.includes(name))
  fireEvent.click(rows[0].querySelector('button[class*="chenxing-link"]') as HTMLButtonElement)
  await screen.findByText('编辑 OAuth 提供商')
}

export function save() {
  const button = screen.getByRole('button', { name: '保存' })
  fireEvent.submit(button.closest('form') as HTMLFormElement)
}

export function openCreate() {
  fireEvent.click(screen.getAllByRole('button', { name: '添加 OAuth 提供商' })[0])
}

/** 填满创建表单的必填项，enable 默认打开（emptyForm.enabled === true） */
export function fillCreateForm(slug = 'okta') {
  fireEvent.change(screen.getByLabelText('显示名称 *'), { target: { value: 'Okta' } })
  fireEvent.change(screen.getByLabelText('Slug *'), { target: { value: slug } })
  fireEvent.change(screen.getByLabelText('Client ID *'), { target: { value: 'client-okta' } })
  fireEvent.change(screen.getByLabelText('Client Secret *'), { target: { value: 'okta-secret' } })
}

export function creates() {
  return requests.filter((r) => r.method === 'POST' && r.path === '/api/v1/admin/oauth/providers')
}

export function enables(slug: string) {
  return requests.filter((r) => r.method === 'POST' && r.path.endsWith(`/${slug}/enable`))
}

export function warnings(onMessage: ReturnType<typeof vi.fn>): string[] {
  return onMessage.mock.calls.filter((call) => call[1] === 'warning').map((call) => String(call[0]))
}

/**
 * 部分成功提示会在 busy 还是 true 的那一帧就渲染出来（setPending 早于 load 完成），
 * 此时按钮带 disabled，点击是空操作。等它变可用再点，避免测试与渲染时序打架。
 */
export async function clickWhenEnabled(button: HTMLElement) {
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false))
  fireEvent.click(button)
}

export async function clickRetryEnable() {
  await clickWhenEnabled(await screen.findByRole('button', { name: '重试启用' }))
}
