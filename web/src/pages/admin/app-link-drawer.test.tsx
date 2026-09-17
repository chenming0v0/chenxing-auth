import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import type { AppLinkResponse, ClientSummary } from '../../api'
import { AppLinkDrawer } from './app-link-drawer'

installCsrfCookie()

type CapturedRequest = { path: string; method?: string; body?: Record<string, unknown> }

const EDITING: AppLinkResponse = {
  client_id: 'cx-1',
  numeric_app_id: 1,
  client_name: 'termux-chrome',
  package_name: 'com.chengming.termux',
  sha256_cert_fingerprints: ['AA:BB'],
}

const SAVED: AppLinkResponse = {
  ...EDITING,
  sha256_cert_fingerprints: ['AA:BB', 'CC:DD'],
}

const PLATFORM: ClientSummary = {
  id: 1,
  numeric_app_id: 1,
  client_id: 'cx-1',
  client_name: 'termux-chrome',
  redirect_uris: ['https://example.com/cb'],
  scopes: ['openid'],
  status: 'active',
  auth_method: 'none',
  quota_exempt: true,
}

const THIRD_PARTY: ClientSummary = {
  ...PLATFORM,
  id: 2,
  numeric_app_id: 2,
  client_id: 'cx-third',
  client_name: '第三方应用',
  quota_exempt: false,
}

let requests: CapturedRequest[] = []
let clients: ClientSummary[] = [PLATFORM, THIRD_PARTY]
let issuer: string | null = 'https://issuer.example'
let respondPut: () => Response

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  requests = []
  clients = [PLATFORM, THIRD_PARTY]
  issuer = 'https://issuer.example'
  respondPut = () => jsonResponse(SAVED)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const url = String(path)
    const method = init?.method ?? 'GET'
    const raw = typeof init?.body === 'string' ? init.body : undefined
    requests.push({ path: url, method, body: raw ? JSON.parse(raw) as Record<string, unknown> : undefined })
    if (url === '/.well-known/openid-configuration') {
      if (issuer === null) return Promise.reject(new Error('offline'))
      return Promise.resolve(jsonResponse({ issuer }))
    }
    if (url.startsWith('/api/v1/admin/clients')) return Promise.resolve(jsonResponse(clients))
    return Promise.resolve(respondPut())
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderDrawer(options: {
  editing?: AppLinkResponse | null
  onSaved?: () => void
  onClose?: () => void
} = {}) {
  render(
    <AppLinkDrawer
      editing={options.editing ?? null}
      onClose={options.onClose ?? (() => {})}
      onSaved={options.onSaved ?? (() => {})}
    />,
  )
}

async function readySelect() {
  const trigger = await screen.findByRole('combobox', { name: '官方应用' })
  await waitFor(() => expect((trigger as HTMLButtonElement).disabled).toBe(false))
  return trigger
}

async function pickOfficial() {
  fireEvent.click(await readySelect())
  fireEvent.click(await screen.findByRole('option', { name: 'termux-chrome · cx-1' }))
}

function fillPackage(values: { packageName?: string; fingerprints?: string } = {}) {
  fireEvent.change(screen.getByLabelText('Android 包名'), { target: { value: values.packageName ?? 'com.example.app' } })
  fireEvent.change(screen.getByLabelText('SHA-256 签名指纹'), { target: { value: values.fingerprints ?? 'AA:BB' } })
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: '保存声明' }))
}

function putRequests() {
  return requests.filter((request) => request.method === 'PUT')
}

describe('AppLinkDrawer 创建：选官方客户端', () => {
  it('列出接入应用和管理面创建的客户端', async () => {
    renderDrawer()
    fireEvent.click(await readySelect())
    expect(await screen.findByRole('option', { name: 'termux-chrome · cx-1' })).toBeTruthy()
    expect(await screen.findByRole('option', { name: '第三方应用 · cx-third' })).toBeTruthy()
    expect(requests.some((request) => request.path === '/api/v1/admin/clients?limit=200')).toBe(true)
  })

  it('没有客户端时禁用提交，并提示先到接入应用创建', async () => {
    clients = []
    renderDrawer()
    expect(await screen.findByText('还没有客户端。先到「接入应用」创建一个公开客户端。')).toBeTruthy()
    await waitFor(() => {
      expect((screen.getByRole('button', { name: '保存声明' }) as HTMLButtonElement).disabled).toBe(true)
    })
    expect(putRequests()).toEqual([])
  })

  it('选中官方客户端后展示 Discovery 里的回调 URL', async () => {
    renderDrawer()
    await pickOfficial()
    expect(screen.getByText('/app/1/oauth/callback')).toBeTruthy()
    expect(await screen.findByText('https://issuer.example/app/1/oauth/callback')).toBeTruthy()
  })

  it('Discovery 失败时只显示路径，并说明完整地址来自配置中的 Issuer', async () => {
    issuer = null
    renderDrawer()
    await pickOfficial()
    expect(screen.getByText('/app/1/oauth/callback')).toBeTruthy()
    await waitFor(() => {
      expect(screen.getByText(/完整地址是配置中的 Issuer 加上这条路径/)).toBeTruthy()
    })
  })
})

describe('AppLinkDrawer 客户端校验', () => {
  it('必填项为空时不发 PUT，并聚焦官方应用选择器', async () => {
    renderDrawer()
    await readySelect()
    submit()
    expect(putRequests()).toEqual([])
    expect(screen.getByText('请选择应用。')).toBeTruthy()
    expect(screen.getByText('请填写 Android 包名。')).toBeTruthy()
    expect(screen.getByText('请至少填写一条签名指纹。')).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByRole('combobox', { name: '官方应用' }))
  })

  it('选择官方应用后清掉该字段的旧错误', async () => {
    renderDrawer()
    await readySelect()
    submit()
    expect(screen.getByText('请选择应用。')).toBeTruthy()
    await pickOfficial()
    expect(screen.queryByText('请选择应用。')).toBeNull()
    expect(screen.getByText('请填写 Android 包名。')).toBeTruthy()
  })
})

describe('AppLinkDrawer 提交', () => {
  it('按行和逗号拆分指纹后发出 PUT', async () => {
    const saved: unknown[] = []
    renderDrawer({ onSaved: () => saved.push(true) })
    await pickOfficial()
    fillPackage({ fingerprints: 'AA:BB\nCC:DD, EE:FF' })
    submit()
    await waitFor(() => expect(saved.length).toBe(1))
    expect(putRequests()).toHaveLength(1)
    expect(putRequests()[0].path).toBe('/api/v1/admin/app-links/cx-1')
    expect(putRequests()[0].body).toEqual({
      package_name: 'com.example.app',
      sha256_cert_fingerprints: ['AA:BB', 'CC:DD', 'EE:FF'],
    })
  })

  it('保存失败时在抽屉内展示警告，不回调 onSaved', async () => {
    const saved: unknown[] = []
    renderDrawer({ onSaved: () => saved.push(true) })
    await pickOfficial()
    fillPackage()
    respondPut = () => jsonResponse({ code: 'not_found' }, 404)
    submit()
    await waitFor(() => expect(screen.getByText('请求的资源不存在或已失效。')).toBeTruthy())
    expect(saved).toEqual([])
    expect(screen.getByRole('dialog')).toBeTruthy()
  })
})

describe('AppLinkDrawer 编辑模式', () => {
  it('客户端只读，仍展示回调 URL，可改包名和指纹', async () => {
    renderDrawer({ editing: EDITING })
    expect(screen.getByText('编辑软件链接')).toBeTruthy()
    expect(screen.getByText('覆盖「termux-chrome」已登记的包名和签名指纹。')).toBeTruthy()
    expect(screen.getByText('这条声明绑定的软件，不能更改。')).toBeTruthy()
    expect(screen.queryByRole('combobox', { name: '官方应用' })).toBeNull()
    expect(screen.getByText('cx-1')).toBeTruthy()
    expect(screen.getByText('/app/1/oauth/callback')).toBeTruthy()
    expect(await screen.findByText('https://issuer.example/app/1/oauth/callback')).toBeTruthy()
    expect((screen.getByLabelText('Android 包名') as HTMLInputElement).value).toBe('com.chengming.termux')
    expect((screen.getByLabelText('SHA-256 签名指纹') as HTMLTextAreaElement).value).toBe('AA:BB')
    expect(requests.some((request) => request.path.startsWith('/api/v1/admin/clients'))).toBe(false)
  })

  it('编辑提交仍用原 Client ID 作为路径键', async () => {
    renderDrawer({ editing: EDITING })
    fireEvent.change(screen.getByLabelText('Android 包名'), { target: { value: 'com.example.app' } })
    fireEvent.change(screen.getByLabelText('SHA-256 签名指纹'), { target: { value: 'AA:BB,CC:DD' } })
    submit()
    await waitFor(() => expect(putRequests()).toHaveLength(1))
    expect(putRequests()[0].path).toBe('/api/v1/admin/app-links/cx-1')
    expect(putRequests()[0].body).toEqual({
      package_name: 'com.example.app',
      sha256_cert_fingerprints: ['AA:BB', 'CC:DD'],
    })
  })
})
