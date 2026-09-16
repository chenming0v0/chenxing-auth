import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import type { AppLinkResponse } from '../../api'
import { AppLinkDrawer } from './app-link-drawer'

installCsrfCookie()

type CapturedRequest = { path: string; method?: string; body: Record<string, unknown> }

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

let requests: CapturedRequest[] = []
let respond: () => Response

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  requests = []
  respond = () => jsonResponse(SAVED)
  vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
    const raw = typeof init?.body === 'string' ? init.body : '{}'
    requests.push({ path, method: init?.method, body: JSON.parse(raw) as Record<string, unknown> })
    return Promise.resolve(respond())
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

function fill(values: { clientId?: string; packageName?: string; fingerprints?: string } = {}) {
  fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: values.clientId ?? 'cx-1' } })
  fireEvent.change(screen.getByLabelText('Android 包名'), { target: { value: values.packageName ?? 'com.example.app' } })
  fireEvent.change(screen.getByLabelText('SHA-256 签名指纹'), { target: { value: values.fingerprints ?? 'AA:BB' } })
}

function submit() {
  fireEvent.click(screen.getByRole('button', { name: '保存声明' }))
}

describe('AppLinkDrawer 客户端校验', () => {
  it('必填项为空时不发请求，并聚焦第一个出错字段', () => {
    renderDrawer()
    submit()
    expect(requests).toEqual([])
    expect(screen.getByText('请填写 Client ID。')).toBeTruthy()
    expect(screen.getByText('请填写 Android 包名。')).toBeTruthy()
    expect(screen.getByText('请至少填写一条签名指纹。')).toBeTruthy()
    expect(document.activeElement).toBe(screen.getByLabelText('Client ID'))
  })

  it('修改字段后清掉该字段的旧错误', () => {
    renderDrawer()
    submit()
    expect(screen.getByText('请填写 Client ID。')).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Client ID'), { target: { value: 'cx-1' } })
    expect(screen.queryByText('请填写 Client ID。')).toBeNull()
    expect(screen.getByText('请填写 Android 包名。')).toBeTruthy()
  })
})

describe('AppLinkDrawer 提交', () => {
  it('按行和逗号拆分指纹后发出 PUT', async () => {
    const saved: unknown[] = []
    renderDrawer({ onSaved: () => saved.push(true) })
    fill({ fingerprints: 'AA:BB\nCC:DD, EE:FF' })
    submit()
    await waitFor(() => expect(saved.length).toBe(1))
    expect(requests).toHaveLength(1)
    expect(requests[0].path).toBe('/api/v1/admin/app-links/cx-1')
    expect(requests[0].method).toBe('PUT')
    expect(requests[0].body).toEqual({
      package_name: 'com.example.app',
      sha256_cert_fingerprints: ['AA:BB', 'CC:DD', 'EE:FF'],
    })
  })

  it('保存失败时在抽屉内展示警告，不回调 onSaved', async () => {
    const saved: unknown[] = []
    renderDrawer({ onSaved: () => saved.push(true) })
    fill()
    respond = () => jsonResponse({ code: 'not_found' }, 404)
    submit()
    await waitFor(() => expect(screen.getByText('请求的资源不存在或已失效。')).toBeTruthy())
    expect(saved).toEqual([])
    expect(screen.getByRole('dialog')).toBeTruthy()
  })
})

describe('AppLinkDrawer 编辑模式', () => {
  it('预填包名和指纹，Client ID 不可改', () => {
    renderDrawer({ editing: EDITING })
    expect(screen.getByText('编辑软件链接')).toBeTruthy()
    expect(screen.getByText('覆盖「termux-chrome」已登记的包名和签名指纹。')).toBeTruthy()
    expect(screen.getByText('这条声明绑定的软件，不能更改。')).toBeTruthy()
    const clientId = screen.getByLabelText('Client ID') as HTMLInputElement
    expect(clientId.value).toBe('cx-1')
    expect(clientId.readOnly).toBe(true)
    expect(clientId.disabled).toBe(false)
    expect((screen.getByLabelText('Android 包名') as HTMLInputElement).value).toBe('com.chengming.termux')
    expect((screen.getByLabelText('SHA-256 签名指纹') as HTMLTextAreaElement).value).toBe('AA:BB')
  })

  it('编辑提交仍用原 Client ID 作为路径键', async () => {
    renderDrawer({ editing: EDITING })
    fireEvent.change(screen.getByLabelText('Android 包名'), { target: { value: 'com.example.app' } })
    fireEvent.change(screen.getByLabelText('SHA-256 签名指纹'), { target: { value: 'AA:BB,CC:DD' } })
    submit()
    await waitFor(() => expect(requests.length).toBe(1))
    expect(requests[0].path).toBe('/api/v1/admin/app-links/cx-1')
    expect(requests[0].body).toEqual({
      package_name: 'com.example.app',
      sha256_cert_fingerprints: ['AA:BB', 'CC:DD'],
    })
  })
})
