import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { OwnedOAuthClient } from '../../api'
import { AppRegisterDrawer } from './app-register-drawer'
import { REDIRECT_URI_RULE_MESSAGE } from './developer-shared'
import { MAX_REDIRECT_URIS } from './redirect-uri-list'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

// 官方回调区块用 useAuth 判断是否展示「去软件链接」；抽屉测试不挂 AuthProvider。
vi.mock('../../auth-state', () => ({
  useAuth: () => ({
    user: {
      id: 1, username: 'chenxing', email: 'chenxing@example.test', display_name: '测试员',
      status: 'active', role: 'user', current_session_expires_at: '2026-08-20T00:00:00Z',
      avatar_updated_at: null,
    },
    status: 'authenticated',
  }),
}))

const OFFICIAL_CALLBACK = 'https://issuer.example/app/1/oauth/callback'

const CLIENT: OwnedOAuthClient = {
  id: 1,
  client_id: 'cx-client-demo',
  client_name: '演示应用',
  redirect_uris: ['https://app.example.com/callback'],
  scopes: ['openid', 'profile'],
  status: 'active',
  quota: { daily_limit: null, daily_used: 0, monthly_limit: null, monthly_used: 0 },
  auth_method: 'client_secret_basic',
  logo_uri: null,
  client_uri: null,
  description: null,
  numeric_app_id: 1,
}

beforeEach(() => {
  apiFetchMock.mockReset()
  apiFetchMock.mockResolvedValue({ ...CLIENT, client_secret: 'cxs_secret', auth_method: 'client_secret_basic' })
  vi.stubGlobal('fetch', (path: string) => (
    String(path) === '/.well-known/openid-configuration'
      ? Promise.resolve({ ok: true, status: 200, json: async () => ({ issuer: 'https://issuer.example' }) } as Response)
      : Promise.reject(new Error(`unexpected fetch ${String(path)}`))
  ))
})
afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderCreate(handlers: { onCreated?: (client: unknown) => void; onUpdated?: () => void; onClose?: () => void } = {}) {
  render(
    <AppRegisterDrawer
      editing={null}
      onClose={handlers.onClose ?? (() => {})}
      onCreated={handlers.onCreated ?? (() => {})}
      onUpdated={handlers.onUpdated ?? (() => {})}
    />,
  )
}

function redirectInput() {
  return screen.getByPlaceholderText('输入后按回车添加')
}

function addRedirectUri(uri: string, via: 'enter' | 'button' = 'enter') {
  const input = redirectInput()
  fireEvent.change(input, { target: { value: uri } })
  if (via === 'button') fireEvent.click(screen.getByRole('button', { name: '添加' }))
  else fireEvent.keyDown(input, { key: 'Enter' })
}

function fillRequired(name = '星尘控制台', redirect = 'https://app.example.com/callback') {
  fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: name } })
  addRedirectUri(redirect)
}

function listedUris() {
  return screen.queryAllByRole('listitem').map((item) => item.querySelector('[title]')?.getAttribute('title') ?? '')
}

function submitCreate() {
  fireEvent.click(screen.getByRole('button', { name: '创建应用' }))
}

function createBody(): Record<string, unknown> | undefined {
  const call = apiFetchMock.mock.calls.find(([path, init]) => path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')
  const raw = call?.[1]?.body
  return typeof raw === 'string' ? JSON.parse(raw) as Record<string, unknown> : undefined
}

function permissionSwitch(name: string) {
  return screen.getByRole('switch', { name })
}

describe('AppRegisterDrawer 创建', () => {
  it('默认机密客户端提交 client_secret_basic，并写入 logo_uri / client_uri', async () => {
    const onCreated = vi.fn()
    renderCreate({ onCreated })
    fillRequired()
    fireEvent.change(screen.getByLabelText('Logo URL（选填）'), { target: { value: 'https://cdn.example.com/logo.png' } })
    fireEvent.change(screen.getByLabelText('应用主页（选填）'), { target: { value: 'https://app.example.com' } })
    submitCreate()

    await waitFor(() => expect(onCreated).toHaveBeenCalled())
    expect(createBody()).toEqual({
      client_name: '星尘控制台',
      redirect_uris: ['https://app.example.com/callback'],
      scopes: ['openid', 'profile', 'email'],
      logo_uri: 'https://cdn.example.com/logo.png',
      client_uri: 'https://app.example.com',
      description: null,
      auth_method: 'client_secret_basic',
    })
  })

  it('公开客户端提交 auth_method=none', async () => {
    renderCreate()
    fillRequired()
    fireEvent.click(screen.getByRole('radio', { name: /公开客户端/ }))
    submitCreate()

    await waitFor(() => expect(createBody()?.auth_method).toBe('none'))
  })

  it('创建时不出现 Android 包名输入和官方回调区块，公开客户端提示编辑页一键加入', () => {
    renderCreate()
    expect(screen.queryByLabelText('Android 包名')).toBeNull()
    fireEvent.click(screen.getByRole('radio', { name: /公开客户端/ }))
    expect(screen.getByText(/第三方填自己的 HTTPS 回调/)).toBeTruthy()
    expect(screen.getByText(/在编辑页可一键加入本 Issuer 的官方回调/)).toBeTruthy()
    expect(screen.queryByText('官方回调（本 Issuer）')).toBeNull()
  })

  it('机密客户端可改为 client_secret_post', async () => {
    renderCreate()
    fillRequired()
    fireEvent.click(screen.getByRole('combobox', { name: '令牌端点认证' }))
    fireEvent.click(screen.getByRole('option', { name: '请求体（client_secret_post）' }))
    submitCreate()

    await waitFor(() => expect(createBody()?.auth_method).toBe('client_secret_post'))
  })

  it('拒绝非 HTTPS 的 Logo URL，不发请求', () => {
    renderCreate()
    fillRequired()
    fireEvent.change(screen.getByLabelText('Logo URL（选填）'), { target: { value: 'http://cdn.example.com/logo.png' } })
    submitCreate()
    expect(screen.getByText('仅允许 HTTPS。')).toBeTruthy()
    expect(apiFetchMock).not.toHaveBeenCalled()
  })

  it('无 Logo 时用应用名首字作为预览', () => {
    renderCreate()
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '星尘控制台' } })
    expect(screen.getByText('星')).toBeTruthy()
    expect(screen.queryByRole('img')).toBeNull()
    expect(screen.getByText('无 Logo 时，同意页使用名称首字')).toBeTruthy()
  })

  it('填写描述后预览展示描述，不再显示 Logo 提示', () => {
    renderCreate()
    fireEvent.change(screen.getByLabelText('应用描述（选填）'), { target: { value: '管理星尘任务' } })
    expect(screen.getAllByText('管理星尘任务').length).toBeGreaterThanOrEqual(2)
    expect(screen.queryByText('无 Logo 时，同意页使用名称首字')).toBeNull()
  })

  it('用权限列表替代 Scope 输入，默认勾选身份标识、基本资料和电子邮箱', () => {
    renderCreate()
    expect(screen.queryByLabelText('Scope')).toBeNull()
    expect(permissionSwitch('身份标识').getAttribute('aria-checked')).toBe('true')
    expect(permissionSwitch('基本资料').getAttribute('aria-checked')).toBe('true')
    expect(permissionSwitch('电子邮箱').getAttribute('aria-checked')).toBe('true')
  })

  it('取消电子邮箱后提交 scopes 不含 email', async () => {
    renderCreate()
    fillRequired()
    fireEvent.click(permissionSwitch('电子邮箱'))
    submitCreate()

    await waitFor(() => expect(createBody()?.scopes).toEqual(['openid', 'profile']))
  })

  it('全部取消勾选时提示至少一项权限，不发请求', () => {
    renderCreate()
    fillRequired()
    fireEvent.click(permissionSwitch('身份标识'))
    fireEvent.click(permissionSwitch('基本资料'))
    fireEvent.click(permissionSwitch('电子邮箱'))
    submitCreate()
    expect(screen.getByText('请至少选择一项权限。')).toBeTruthy()
    expect(document.activeElement?.id).toBe('app-register-scopes')
    expect(apiFetchMock).not.toHaveBeenCalled()
  })

  it('应用描述去首尾空格后提交', async () => {
    renderCreate()
    fillRequired()
    fireEvent.change(screen.getByLabelText('应用描述（选填）'), { target: { value: '  星尘控制台的说明  ' } })
    submitCreate()

    await waitFor(() => expect(createBody()?.description).toBe('星尘控制台的说明'))
  })

  it('应用描述超过 512 个字符时不发请求', () => {
    renderCreate()
    fillRequired()
    fireEvent.change(screen.getByLabelText('应用描述（选填）'), { target: { value: '测'.repeat(513) } })
    submitCreate()
    expect(screen.getByText('应用描述最多 512 个字符。')).toBeTruthy()
    expect(apiFetchMock).not.toHaveBeenCalled()
  })
})

describe('AppRegisterDrawer 编辑', () => {
  it('可改 Logo 与主页，类型只读，PUT 体不含 auth_method', async () => {
    const onUpdated = vi.fn()
    apiFetchMock.mockResolvedValue(undefined)
    render(
      <AppRegisterDrawer
        editing={CLIENT}
        onClose={() => {}}
        onCreated={() => {}}
        onUpdated={onUpdated}
      />,
    )
    expect(screen.getByLabelText('Logo URL（选填）')).toBeTruthy()
    expect(screen.queryByRole('radio', { name: /公开客户端/ })).toBeNull()
    expect(screen.getByText('机密客户端')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Logo URL（选填）'), { target: { value: 'https://cdn.example.com/logo.png' } })
    fireEvent.click(screen.getByRole('button', { name: '保存更新' }))
    await waitFor(() => expect(onUpdated).toHaveBeenCalled())
    const put = apiFetchMock.mock.calls.find(([path, init]) =>
      typeof path === 'string' && path.includes('/oauth-clients/') && init?.method === 'PUT')
    expect(JSON.parse(String(put?.[1]?.body))).toEqual({
      client_name: '演示应用',
      redirect_uris: ['https://app.example.com/callback'],
      scopes: ['openid', 'profile'],
      logo_uri: 'https://cdn.example.com/logo.png',
      client_uri: null,
      description: null,
    })
  })

  it('PUT 体带上填写的应用描述', async () => {
    const onUpdated = vi.fn()
    apiFetchMock.mockResolvedValue(undefined)
    render(
      <AppRegisterDrawer
        editing={CLIENT}
        onClose={() => {}}
        onCreated={() => {}}
        onUpdated={onUpdated}
      />,
    )
    fireEvent.change(screen.getByLabelText('应用描述（选填）'), { target: { value: '演示用应用' } })
    fireEvent.click(screen.getByRole('button', { name: '保存更新' }))
    await waitFor(() => expect(onUpdated).toHaveBeenCalled())
    const put = apiFetchMock.mock.calls.find(([path, init]) =>
      typeof path === 'string' && path.includes('/oauth-clients/') && init?.method === 'PUT')
    expect(JSON.parse(String(put?.[1]?.body)).description).toBe('演示用应用')
  })

  it('编辑时列出已有 Redirect URI', () => {
    render(
      <AppRegisterDrawer
        editing={{ ...CLIENT, redirect_uris: ['https://app.example.com/callback', 'https://app.example.com/oauth'] }}
        onClose={() => {}}
        onCreated={() => {}}
        onUpdated={() => {}}
      />,
    )
    expect(listedUris()).toEqual(['https://app.example.com/callback', 'https://app.example.com/oauth'])
    expect(screen.getByRole('button', { name: '移除 https://app.example.com/callback' })).toBeTruthy()
    expect(redirectInput().tagName).toBe('INPUT')
  })

  it('编辑时保留目录外的已有权限，不会悄悄丢掉', async () => {
    const onUpdated = vi.fn()
    apiFetchMock.mockResolvedValue(undefined)
    render(
      <AppRegisterDrawer
        editing={{ ...CLIENT, scopes: ['openid', 'profile', 'custom_scope'] }}
        onClose={() => {}}
        onCreated={() => {}}
        onUpdated={onUpdated}
      />,
    )
    expect(permissionSwitch('custom_scope').getAttribute('aria-checked')).toBe('true')
    fireEvent.click(screen.getByRole('button', { name: '保存更新' }))
    await waitFor(() => expect(onUpdated).toHaveBeenCalled())
    const put = apiFetchMock.mock.calls.find(([path, init]) =>
      typeof path === 'string' && path.includes('/oauth-clients/') && init?.method === 'PUT')
    expect(JSON.parse(String(put?.[1]?.body)).scopes).toEqual(['openid', 'profile', 'custom_scope'])
  })
})

describe('AppRegisterDrawer 编辑公开客户端的官方回调', () => {
  const PUBLIC: OwnedOAuthClient = { ...CLIENT, auth_method: 'none' }

  function renderEdit(client: OwnedOAuthClient, onUpdated = () => {}) {
    render(<AppRegisterDrawer editing={client} onClose={() => {}} onCreated={() => {}} onUpdated={onUpdated} />)
  }

  it('机密客户端不显示官方回调区块', () => {
    renderEdit(CLIENT)
    expect(screen.queryByText('官方回调（本 Issuer）')).toBeNull()
  })

  it('显示完整官方回调 URL，一键加入回调列表后按钮变为已加入并随 PUT 提交', async () => {
    const onUpdated = vi.fn()
    apiFetchMock.mockResolvedValue(undefined)
    renderEdit(PUBLIC, onUpdated)
    expect(screen.getByText('官方回调（本 Issuer）')).toBeTruthy()
    expect(screen.getByText('/app/1/oauth/callback')).toBeTruthy()
    expect(await screen.findByText(OFFICIAL_CALLBACK)).toBeTruthy()
    expect(screen.queryByRole('link', { name: '去软件链接' })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: '加入回调列表' }))
    expect(listedUris()).toEqual(['https://app.example.com/callback', OFFICIAL_CALLBACK])
    const added = screen.getByRole('button', { name: '已加入' })
    expect(added.hasAttribute('disabled')).toBe(true)

    fireEvent.click(screen.getByRole('button', { name: '保存更新' }))
    await waitFor(() => expect(onUpdated).toHaveBeenCalled())
    const put = apiFetchMock.mock.calls.find(([path, init]) =>
      typeof path === 'string' && path.includes('/oauth-clients/') && init?.method === 'PUT')
    expect(JSON.parse(String(put?.[1]?.body)).redirect_uris).toEqual(['https://app.example.com/callback', OFFICIAL_CALLBACK])
  })

  it('官方回调已在列表时直接显示已加入', async () => {
    renderEdit({ ...PUBLIC, redirect_uris: [OFFICIAL_CALLBACK] })
    expect((await screen.findByRole('button', { name: '已加入' })).hasAttribute('disabled')).toBe(true)
    expect(screen.queryByRole('button', { name: '加入回调列表' })).toBeNull()
  })

  it('回调列表已满时禁用加入并提示', async () => {
    const full = Array.from({ length: MAX_REDIRECT_URIS }, (_, index) => `https://app.example.com/cb-${index}`)
    renderEdit({ ...PUBLIC, redirect_uris: full })
    await screen.findByText(OFFICIAL_CALLBACK)
    expect(screen.getByRole('button', { name: '加入回调列表' }).hasAttribute('disabled')).toBe(true)
    expect(screen.getByText('回调列表已满，先移除一条再加入。')).toBeTruthy()
  })

  it('取不到 Issuer 时只展示路径并禁用加入', async () => {
    vi.stubGlobal('fetch', () => Promise.reject(new Error('offline')))
    renderEdit(PUBLIC)
    expect(await screen.findByText('完整地址是配置中的 Issuer 加上这条路径。')).toBeTruthy()
    expect(screen.getByRole('button', { name: '加入回调列表' }).hasAttribute('disabled')).toBe(true)
    expect(screen.queryByText(OFFICIAL_CALLBACK)).toBeNull()
  })
})

describe('AppRegisterDrawer Redirect URI 列表', () => {
  it('回车把 URI 加入列表并清空输入框，且不提交表单', () => {
    renderCreate()
    expect(screen.getByLabelText('Redirect URI').tagName).toBe('INPUT')
    addRedirectUri('https://app.example.com/callback')
    expect(listedUris()).toEqual(['https://app.example.com/callback'])
    expect((redirectInput() as HTMLInputElement).value).toBe('')
    expect(apiFetchMock).not.toHaveBeenCalled()
    expect(screen.queryByText('请填写应用名称。')).toBeNull()
  })

  it('添加按钮同样写入列表并清空输入框', () => {
    renderCreate()
    addRedirectUri('https://app.example.com/callback', 'button')
    expect(listedUris()).toEqual(['https://app.example.com/callback'])
    expect((redirectInput() as HTMLInputElement).value).toBe('')
  })

  it('拒绝重复项，列表保持唯一', () => {
    renderCreate()
    addRedirectUri('https://app.example.com/callback')
    addRedirectUri('https://app.example.com/callback')
    expect(screen.getByText('该 Redirect URI 已添加。')).toBeTruthy()
    expect(listedUris()).toEqual(['https://app.example.com/callback'])
    expect((redirectInput() as HTMLInputElement).value).toBe('https://app.example.com/callback')
  })

  it('拒绝非法 URI，不写入列表，并展示 HTTPS / 回环规则', () => {
    renderCreate()
    addRedirectUri('http://example.com/callback')
    expect(listedUris()).toEqual([])
    expect(screen.getByText(`「http://example.com/callback」仅允许 HTTPS，或 HTTP 回环地址（127.0.0.1 / [::1]）。${REDIRECT_URI_RULE_MESSAGE}`)).toBeTruthy()
    expect(screen.queryByRole('button', { name: '移除 http://example.com/callback' })).toBeNull()
  })

  it('移除按钮删掉对应项', () => {
    renderCreate()
    addRedirectUri('https://app.example.com/callback')
    addRedirectUri('https://app.example.com/oauth')
    fireEvent.click(screen.getByRole('button', { name: '移除 https://app.example.com/callback' }))
    expect(listedUris()).toEqual(['https://app.example.com/oauth'])
    expect(screen.getByText('https://app.example.com/oauth')).toBeTruthy()
  })

  it('列表为空时提交不发请求', () => {
    renderCreate()
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '星尘控制台' } })
    submitCreate()
    expect(screen.getByText('请至少添加一个 Redirect URI。')).toBeTruthy()
    expect(document.activeElement).toBe(redirectInput())
    expect(apiFetchMock).not.toHaveBeenCalled()
  })

  it('提交时把未确认的合法草稿一并写入 redirect_uris', async () => {
    renderCreate()
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '星尘控制台' } })
    fireEvent.change(redirectInput(), { target: { value: 'https://app.example.com/callback' } })
    submitCreate()
    await waitFor(() => expect(createBody()?.redirect_uris).toEqual(['https://app.example.com/callback']))
  })

  it('提交时未确认的非法草稿留在输入框，不发请求', () => {
    renderCreate()
    fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: '星尘控制台' } })
    fireEvent.change(redirectInput(), { target: { value: 'http://example.com/callback' } })
    submitCreate()
    expect(apiFetchMock).not.toHaveBeenCalled()
    expect((redirectInput() as HTMLInputElement).value).toBe('http://example.com/callback')
    expect(document.activeElement).toBe(redirectInput())
    expect(screen.getByText(`「http://example.com/callback」仅允许 HTTPS，或 HTTP 回环地址（127.0.0.1 / [::1]）。${REDIRECT_URI_RULE_MESSAGE}`)).toBeTruthy()
  })

  it('拒绝第 11 个 Redirect URI', () => {
    renderCreate()
    for (let index = 0; index < MAX_REDIRECT_URIS; index += 1) {
      addRedirectUri(`https://app.example.com/cb-${index}`)
    }
    addRedirectUri('https://app.example.com/cb-overflow')
    expect(screen.getByText(`最多添加 ${MAX_REDIRECT_URIS} 个 Redirect URI。`)).toBeTruthy()
    expect(listedUris()).toHaveLength(MAX_REDIRECT_URIS)
    expect((redirectInput() as HTMLInputElement).value).toBe('https://app.example.com/cb-overflow')
  })
})
