import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { OwnedOAuthClient } from '../../api'
import { AppRegisterDrawer } from './app-register-drawer'

const { apiFetchMock } = vi.hoisted(() => ({
  apiFetchMock: vi.fn((_path: string, _init?: RequestInit): Promise<unknown> => Promise.resolve({})),
}))

vi.mock('../../api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../api')>()),
  apiFetch: apiFetchMock,
}))

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
}

beforeEach(() => {
  apiFetchMock.mockReset()
  apiFetchMock.mockResolvedValue({ ...CLIENT, client_secret: 'cxs_secret', auth_method: 'client_secret_basic' })
})
afterEach(() => cleanup())

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

function fillRequired(name = '星尘控制台', redirect = 'https://app.example.com/callback') {
  fireEvent.change(screen.getByLabelText('应用名称'), { target: { value: name } })
  fireEvent.change(screen.getByLabelText('Redirect URI'), { target: { value: redirect } })
}

function submitCreate() {
  fireEvent.click(screen.getByRole('button', { name: '创建应用' }))
}

function createBody(): Record<string, unknown> | undefined {
  const call = apiFetchMock.mock.calls.find(([path, init]) => path === '/api/v1/auth/oauth-clients' && init?.method === 'POST')
  const raw = call?.[1]?.body
  return typeof raw === 'string' ? JSON.parse(raw) as Record<string, unknown> : undefined
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
      scopes: ['openid', 'profile'],
      logo_uri: 'https://cdn.example.com/logo.png',
      client_uri: 'https://app.example.com',
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
    })
  })
})
