/**
 * 外部身份绑定跳转必须先过 http(s) 白名单（#584）。
 * API 返回的 authorization_url 直接喂给 location.assign 时，javascript: / data:
 * 会在应用源下执行；这里覆盖导航汇点，不依赖父页是否展示 notice。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { ExternalIdentities } from './external-identities'

installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

/** jsdom 的 location.assign 会触发未实现的导航告警，测试里换成可断言的桩。 */
function stubLocationAssign(): ReturnType<typeof vi.fn> {
  const assign = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: {
      href: window.location.href,
      origin: window.location.origin,
      protocol: window.location.protocol,
      host: window.location.host,
      hostname: window.location.hostname,
      port: window.location.port,
      pathname: window.location.pathname,
      search: window.location.search,
      hash: window.location.hash,
      assign,
      replace: assign,
      reload: vi.fn(),
      toString: () => window.location.href,
    },
  })
  return assign
}

const originalLocationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')

function renderBindings() {
  const onNotice = vi.fn()
  const view = render(
    <ExternalIdentities
      userEmail="user@chenxing.star"
      busy={null}
      onBusy={vi.fn()}
      onNotice={onNotice}
    />,
  )
  return { onNotice, ...view }
}

beforeEach(() => {
  window.history.replaceState({}, '', '/console/profile')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
  if (originalLocationDescriptor) {
    Object.defineProperty(window, 'location', originalLocationDescriptor)
  }
})

describe('ExternalIdentities 绑定跳转白名单（#584）', () => {
  it('合法 https 授权地址才交给 location.assign', async () => {
    const assign = stubLocationAssign()
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/external-identities' && !init?.method) {
        return Promise.resolve(jsonResponse({ items: [] }))
      }
      if (path === '/api/v1/auth/external-providers') {
        return Promise.resolve(jsonResponse([{ slug: 'google', name: 'Google' }]))
      }
      if (path === '/api/v1/auth/external-identities/google/bind' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ authorization_url: 'https://provider.example/authorize?client_id=1' }))
      }
      return Promise.reject(new Error(`unexpected request: ${init?.method ?? 'GET'} ${path}`))
    })

    renderBindings()
    fireEvent.click(await screen.findByRole('button', { name: '绑定 Google' }))

    await waitFor(() => {
      expect(assign).toHaveBeenCalledWith('https://provider.example/authorize?client_id=1')
    })
  })

  it.each([
    { label: 'javascript:', url: 'javascript:alert(1)' },
    { label: 'data:', url: 'data:text/html,hello' },
    { label: 'empty', url: '' },
    { label: 'malformed', url: 'http://[' },
  ] as const)('拒绝 $label 授权地址，不导航', async ({ url: authorizationUrl }) => {
    const assign = stubLocationAssign()
    vi.stubGlobal('fetch', (path: string, init?: RequestInit) => {
      if (path === '/api/v1/auth/external-identities' && !init?.method) {
        return Promise.resolve(jsonResponse({ items: [] }))
      }
      if (path === '/api/v1/auth/external-providers') {
        return Promise.resolve(jsonResponse([{ slug: 'google', name: 'Google' }]))
      }
      if (path === '/api/v1/auth/external-identities/google/bind' && init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ authorization_url: authorizationUrl }))
      }
      return Promise.reject(new Error(`unexpected request: ${init?.method ?? 'GET'} ${path}`))
    })

    const { onNotice } = renderBindings()
    fireEvent.click(await screen.findByRole('button', { name: '绑定 Google' }))

    await waitFor(() => {
      expect(onNotice).toHaveBeenCalledWith({
        text: '外部授权入口不可用，请稍后重试。',
        tone: 'warning',
      })
    })
    expect(assign).not.toHaveBeenCalled()
  })
})
