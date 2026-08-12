import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import type { OAuthProviderSummary } from '../../../api'
import { installCsrfCookie } from '../../../test/csrf-cookie'
import { OAuthProvidersPanel } from './oauth-providers-panel'

// 提供商的增删改启停都是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

type CapturedRequest = { path: string; method?: string; body: Record<string, unknown> }

let requests: CapturedRequest[] = []
let providers: OAuthProviderSummary[]
/** slug -> 该 slug 的 enable 还要失败几次；用来构造「落库成功、状态切换失败」的部分成功 */
let enableFailures: Map<string, number>

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
  email_verified_claim: 'email_verified',
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

const PROVIDERS_PATH = '/api/v1/admin/oauth/providers'

function setStatus(slug: string, status: 'active' | 'disabled') {
  providers = providers.map((item) => (item.slug === slug ? { ...item, status } : item))
}

/**
 * 有状态的假后端：创建落库后 provider 默认停用（与 openapi 的 201 语义一致），
 * enable / disable 单独改状态。只有这样才能区分「创建失败」和「创建成功但启用失败」。
 */
function handle(path: string, method: string, body: Record<string, unknown>): Response {
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

function renderPanel() {
  const onMessage = vi.fn()
  render(<OAuthProvidersPanel onMessage={onMessage} onDirtyChange={() => {}} />)
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

function openCreate() {
  fireEvent.click(screen.getAllByRole('button', { name: '添加 OAuth 提供商' })[0])
}

/** 填满创建表单的必填项，enable 默认打开（emptyForm.enabled === true） */
function fillCreateForm(slug = 'okta') {
  fireEvent.change(screen.getByLabelText('显示名称 *'), { target: { value: 'Okta' } })
  fireEvent.change(screen.getByLabelText('Slug *'), { target: { value: slug } })
  fireEvent.change(screen.getByLabelText('Client ID *'), { target: { value: 'client-okta' } })
  fireEvent.change(screen.getByLabelText('Client Secret *'), { target: { value: 'okta-secret' } })
}

function creates() {
  return requests.filter((r) => r.method === 'POST' && r.path === '/api/v1/admin/oauth/providers')
}

function enables(slug: string) {
  return requests.filter((r) => r.method === 'POST' && r.path.endsWith(`/${slug}/enable`))
}

function warnings(onMessage: ReturnType<typeof vi.fn>): string[] {
  return onMessage.mock.calls.filter((call) => call[1] === 'warning').map((call) => String(call[0]))
}

/**
 * 部分成功提示会在 busy 还是 true 的那一帧就渲染出来（setPending 早于 load 完成），
 * 此时按钮带 disabled，点击是空操作。等它变可用再点，避免测试与渲染时序打架。
 */
async function clickWhenEnabled(button: HTMLElement) {
  await waitFor(() => expect((button as HTMLButtonElement).disabled).toBe(false))
  fireEvent.click(button)
}

async function clickRetryEnable() {
  await clickWhenEnabled(await screen.findByRole('button', { name: '重试启用' }))
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

  it('编辑未配置提供商时给出明确警告，必填校验走自定义分支而非原生 required（Issue #403）', async () => {
    renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    const input = screen.getByLabelText('Client Secret *') as HTMLInputElement
    /* 原生 required 会在 onSubmit 之前拦截提交，用浏览器英文气泡遮蔽中文警告；
       必填语义由 submit() 中的自定义校验承担，这里断言原生属性未启用。 */
    expect(input.required).toBe(false)
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

describe('OAuthProvidersPanel 信任模型披露（Issue #296）', () => {
  it('面板说明写清 OAuth 2.0 + UserInfo，不宣称 OIDC', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    expect(screen.getByText(/身份字段只取自 UserInfo 响应，本平台不验证 ID Token/)).toBeTruthy()
    expect(screen.getByRole('heading', { name: '自定义 OAuth 2.0 提供商' })).toBeTruthy()
  })

  it('表单弹层给出信任模型提示，并说明 openid scope 的实际作用', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    await openEditRow('GitLab')
    expect(screen.getByText(/信任模型：OAuth 2.0 \+ UserInfo/)).toBeTruthy()
    const scopes = screen.getByLabelText('Scopes *') as HTMLInputElement
    expect(screen.getByText(/不会验证随之返回的 ID Token/)).toBeTruthy()
    // 约束必须通过 aria-describedby 关联到控件，读屏用户才拿得到。
    expect(scopes.getAttribute('aria-describedby')).toBeTruthy()
  })
})

describe('OAuthProvidersPanel Email Verified Claim', () => {
  it('表单字段标记必填，并说明缺失时会拒绝登录', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    await openEditRow('GitLab')
    const input = screen.getByLabelText('Email Verified Claim *') as HTMLInputElement
    expect(input.required).toBe(true)
    expect(input.value).toBe('email_verified')
    expect(screen.getByText(/必须指向布尔值/)).toBeTruthy()
    // 说明文案必须通过 aria-describedby 关联到控件，否则读屏用户拿不到这条约束。
    expect(input.getAttribute('aria-describedby')).toBeTruthy()
  })

  it('提交时按普通字符串发送，不再降级成 null', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    await openEditRow('GitLab')
    save()
    const put = requests.find((r) => r.method === 'PUT')
    expect(put?.body.email_verified_claim).toBe('email_verified')
  })

  it('存量 provider 缺少该 claim 时在列表里给出警告徽标', async () => {
    providers = [{ ...CONFIGURED, email_verified_claim: null }]
    renderPanel()
    await screen.findByText('GitLab')
    expect(screen.getByText('缺少 Email Verified Claim')).toBeTruthy()
  })
})

describe('OAuthProvidersPanel 创建成功但启用失败（Issue #277）', () => {
  it('提示已创建但启用失败，而不是笼统的保存失败', async () => {
    enableFailures.set('okta', 1)
    const onMessage = renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    await waitFor(() => expect(warnings(onMessage).length).toBe(1))
    const message = warnings(onMessage)[0]
    expect(message).toMatch(/Okta 已创建成功，但启用失败/)
    expect(message).toMatch(/外部身份源配置不完整/)
    expect(message).toMatch(/可直接重试启用/)
    // 创建这一步是成功的，不能再报成保存失败
    expect(message).not.toMatch(/保存失败/)
    expect(onMessage).not.toHaveBeenCalledWith('OAuth 提供商已创建。')
  })

  it('关闭弹层并刷新列表，把新 provider 以已禁用状态展示出来', async () => {
    enableFailures.set('okta', 1)
    renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    const cell = await screen.findByText('Okta')
    const row = cell.closest('tr') as HTMLTableRowElement
    expect(row.textContent).toContain('已禁用')
    expect(row.textContent).toContain('启用失败')
    // 弹层必须关掉，否则用户会以为没保存成而重复提交
    expect(screen.queryByText('添加 OAuth 提供商', { selector: 'h2' })).toBeNull()
  })

  it('重试只重放启用，不会再次创建而撞 slug 冲突', async () => {
    enableFailures.set('okta', 1)
    const onMessage = renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    await clickRetryEnable()

    await waitFor(() => expect(onMessage).toHaveBeenCalledWith('已启用 Okta。'))
    expect(creates().length).toBe(1)
    expect(enables('okta').length).toBe(2)
    expect(requests.some((r) => r.method === 'PUT')).toBe(false)
  })

  it('重试成功后提示消失，列表显示已启用', async () => {
    enableFailures.set('okta', 1)
    renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    await clickRetryEnable()
    await waitFor(() => expect(screen.queryByRole('button', { name: '重试启用' })).toBeNull())
    const row = screen.getByText('Okta').closest('tr') as HTMLTableRowElement
    expect(row.textContent).toContain('已启用')
    expect(row.textContent).not.toContain('启用失败')
  })

  it('重试再次失败时保留重试入口，仍然不发起创建', async () => {
    enableFailures.set('okta', 2)
    const onMessage = renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    await clickRetryEnable()
    await waitFor(() => expect(warnings(onMessage).length).toBe(2))
    expect(await screen.findByRole('button', { name: '重试启用' })).toBeTruthy()
    expect(creates().length).toBe(1)
  })

  it('忽略后提示关闭，provider 仍留在列表里', async () => {
    enableFailures.set('okta', 1)
    renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    fillCreateForm()
    save()

    await clickWhenEnabled(await screen.findByRole('button', { name: '忽略' }))
    expect(screen.queryByRole('button', { name: '重试启用' })).toBeNull()
    expect(screen.getByText('Okta')).toBeTruthy()
  })

  it('创建本身失败时仍然按保存失败处理，不给出重试启用入口', async () => {
    const onMessage = renderPanel()
    await screen.findByText('GitLab')
    openCreate()
    // 与既有 gitlab 撞 slug：后端返回 409，创建这一步没成功
    fillCreateForm('gitlab')
    save()

    await waitFor(() => expect(warnings(onMessage).length).toBe(1))
    expect(warnings(onMessage)[0]).toMatch(/请求与当前数据冲突/)
    expect(screen.queryByRole('button', { name: '重试启用' })).toBeNull()
    expect(enables('gitlab').length).toBe(0)
  })
})

describe('OAuthProvidersPanel 更新成功但状态切换失败（Issue #277）', () => {
  it('区分配置已保存与启用失败，并只重试启用', async () => {
    enableFailures.set('gitea', 1)
    const onMessage = renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    fireEvent.change(screen.getByLabelText('Client Secret *'), { target: { value: 'new-secret' } })
    fireEvent.click(screen.getByRole('switch', { name: '启用供应商' }))
    save()

    await waitFor(() => expect(warnings(onMessage).length).toBe(1))
    expect(warnings(onMessage)[0]).toMatch(/Gitea 的配置已保存成功，但启用失败/)
    expect(requests.filter((r) => r.method === 'PUT').length).toBe(1)

    await clickRetryEnable()
    await waitFor(() => expect(onMessage).toHaveBeenCalledWith('已启用 Gitea。'))
    // 重试不重发配置写入
    expect(requests.filter((r) => r.method === 'PUT').length).toBe(1)
    expect(creates().length).toBe(0)
  })

  it('provider 通过其他途径变为目标状态后，重试提示自行消失', async () => {
    enableFailures.set('gitea', 1)
    renderPanel()
    await screen.findByText('Gitea')
    await openEditRow('Gitea')
    fireEvent.change(screen.getByLabelText('Client Secret *'), { target: { value: 'new-secret' } })
    fireEvent.click(screen.getByRole('switch', { name: '启用供应商' }))
    save()

    await screen.findByRole('button', { name: '重试启用' })
    // 行内「启用」动作成功后，列表状态已达目标，提示不该继续挂着
    const row = screen.getByText('Gitea').closest('tr') as HTMLTableRowElement
    const rowEnable = Array.from(row.querySelectorAll('button')).find((button) => button.textContent === '启用')
    await clickWhenEnabled(rowEnable as HTMLButtonElement)
    await waitFor(() => expect(screen.queryByRole('button', { name: '重试启用' })).toBeNull())
  })
})

describe('OAuthProvidersPanel 加载与空态（Issue #388）', () => {
  it('reload 期间只保留数据行，不再叠加「正在加载」空行', async () => {
    renderPanel()
    await screen.findByText('GitLab')
    /* 让 reload 的 GET 挂起，构造「loading === true 且 providers 仍持有旧数据」的窗口。
       行内操作（POST）仍走原 handle，只有列表刷新挂起。 */
    const pending = new Promise<Response>(() => {})
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      const method = init?.method ?? 'GET'
      if (method === 'GET') return pending
      const raw = typeof init?.body === 'string' ? init.body : '{}'
      return Promise.resolve(handle(path, method, JSON.parse(raw) as Record<string, unknown>))
    })
    fireEvent.click(screen.getByRole('button', { name: '禁用' }))
    // 加载窗口内：数据行必须还在，加载空行不得同时出现
    await waitFor(() => expect(screen.queryByText('正在加载 OAuth 提供商。')).toBeNull())
    expect(screen.getByText('GitLab')).toBeTruthy()
  })
})
