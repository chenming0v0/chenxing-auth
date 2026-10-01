import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen, within } from '@testing-library/react'
import type { ResourceServiceBinding } from '../../resource-services-types'
import { formatDate } from '../../data'
import { ResourceServiceBindingCard } from './resource-service-binding-card'

const BINDING: ResourceServiceBinding = {
  id: 'binding-42',
  provider_id: 'provider-1',
  issuer: 'https://provider.example.com',
  uid: 'cltermux:42',
  account: '42',
  name: null,
  status: 'active',
  snapshot: {},
  grant_expires_at: null,
  access_expires_at: null,
  refresh_expires_at: null,
}
const BROWSER_LABEL = 'chrome-termux（浏览器版）登录状态'
const WEBVIEW_LABEL = 'termux-chrome（WebView 版）登录状态'

function renderCard(fields: unknown[], overrides: Partial<ResourceServiceBinding> = {}, providerName = '可编辑的资源服务名称') {
  render(<ResourceServiceBindingCard
    binding={{ ...BINDING, snapshot: { fields, fetched_at: '2026-09-28T00:00:00Z' }, ...overrides }}
    providerName={providerName}
    busy={false}
    pending={false}
    onSync={vi.fn()}
    onRefresh={vi.fn()}
    onUnlink={vi.fn()}
  />)
}

function expectProduct(label: string, status: string) {
  const item = screen.getByText(label).parentElement!
  expect(within(item).getByText(status).tagName).toBe('DD')
}

afterEach(cleanup)

describe('CLtermux product login snapshot', () => {
  it.each([
    ['unbound', '未绑定', 'logged_in', '已登录'],
    ['logged_out', '未登录', 'unbound', '未绑定'],
    ['logged_in', '已登录', 'logged_out', '未登录'],
  ])('shows both independent products: %s / %s', (browser, browserLabel, webview, webviewLabel) => {
    renderCard([
      { key: 'chrome_termux_login', label: '浏览器版登录状态', type: 'status', value: browser },
      { key: 'termux_chrome_login', label: 'WebView 版登录状态', type: 'status', value: webview },
      { key: 'device_status', label: '设备状态', type: 'status', value: 'bound' },
    ])
    expectProduct(BROWSER_LABEL, browserLabel)
    expectProduct(WEBVIEW_LABEL, webviewLabel)
    expect(screen.queryByText('设备状态')).toBeNull()
    expect(screen.queryByText('浏览器版登录状态')).toBeNull()
    expect(screen.getByText('最近同步')).toBeTruthy()
    expect(screen.getByText(formatDate('2026-09-28T00:00:00Z'))).toBeTruthy()
    expect(screen.getByText('登录状态以最近同步结果为准，不表示实时在线。')).toBeTruthy()
  })

  it.each([
    { type: 'text', value: 'unbound' },
    { type: 'boolean', value: false },
    { type: 'status', value: null },
    { type: 'status', value: 'online' },
  ])('shows unknown instead of guessing from malformed product fields: %j', (field) => {
    renderCard([
      { key: 'chrome_termux_login', label: '浏览器版登录状态', ...field },
      { key: 'termux_chrome_login', label: 'WebView 版登录状态', ...field },
    ])
    expectProduct(BROWSER_LABEL, '未知')
    expectProduct(WEBVIEW_LABEL, '未知')
    expect(screen.queryByText('未绑定')).toBeNull()
  })

  it('shows unknown for an old snapshot, even when the aggregate device field says bound', () => {
    renderCard([{ key: 'device_status', label: '设备状态', type: 'status', value: 'bound' }])
    expectProduct(BROWSER_LABEL, '未知')
    expectProduct(WEBVIEW_LABEL, '未知')
    expect(screen.queryByText('未绑定')).toBeNull()
    expect(screen.queryByText('设备状态')).toBeNull()
  })

  it('does not guess CLtermux from the display name or snapshot UID of a generic provider', () => {
    renderCard([], {
      uid: 'generic:42',
      snapshot: { uid: 'cltermux:42', fields: [
        { key: 'device_status', label: '通用设备状态', type: 'status', value: 'bound' },
        { key: 'chrome_termux_login', label: '提供方自己的字段', type: 'text', value: '原样展示' },
      ] },
    }, 'CLtermux')
    expect(screen.queryByText(BROWSER_LABEL)).toBeNull()
    expect(screen.queryByText(WEBVIEW_LABEL)).toBeNull()
    expect(screen.getByText('通用设备状态')).toBeTruthy()
    expect(screen.getByText('已绑定')).toBeTruthy()
    expect(screen.getByText('原样展示')).toBeTruthy()
    expect(screen.queryByText('登录状态以最近同步结果为准，不表示实时在线。')).toBeNull()
  })
})
