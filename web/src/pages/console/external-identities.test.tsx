/**
 * 外部身份绑定跳转必须先过 http(s) 白名单（#584）。
 * API 返回的 authorization_url 直接喂给 location.assign 时，javascript: / data:
 * 会在应用源下执行；这里覆盖导航汇点，不依赖父页是否展示 notice。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { StrictMode } from 'react'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { ExternalIdentities } from './external-identities'

installCsrfCookie()

type Deferred<T> = { promise: Promise<T>; resolve: (value: T) => void }

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((resolvePromise) => { resolve = resolvePromise })
  return { promise, resolve }
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

function renderBindings(strict = false) {
  const onNotice = vi.fn()
  const bindings = (
    <ExternalIdentities
      userEmail="user@chenxing.star"
      busy={null}
      onBusy={vi.fn()}
      onNotice={onNotice}
    />
  )
  const view = render(
    strict ? <StrictMode>{bindings}</StrictMode> : bindings,
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

describe('ExternalIdentities 加载顺序（#675）', () => {
  it('retry 成功后忽略最后返回的旧加载结果和错误', async () => {
    const staleIdentities = deferred<Response>()
    const staleProviders = deferred<Response>()
    const retryIdentities = deferred<Response>()
    const retryProviders = deferred<Response>()
    let identityCalls = 0
    let providerCalls = 0
    vi.stubGlobal('fetch', (path: string) => {
      if (path === '/api/v1/auth/external-identities') {
        identityCalls += 1
        if (identityCalls === 1) return staleIdentities.promise
        if (identityCalls === 2) return Promise.resolve(jsonResponse({ code: 'temporarily_unavailable' }, 503))
        return retryIdentities.promise
      }
      if (path === '/api/v1/auth/external-providers') {
        providerCalls += 1
        if (providerCalls === 1) return staleProviders.promise
        if (providerCalls === 2) return Promise.resolve(jsonResponse([]))
        return retryProviders.promise
      }
      return Promise.reject(new Error(`unexpected request: ${path}`))
    })

    const { onNotice } = renderBindings(true)
    const retry = await screen.findByRole('button', { name: '重试' })
    onNotice.mockClear()
    fireEvent.click(retry)

    await waitFor(() => {
      expect(identityCalls).toBe(3)
      expect(providerCalls).toBe(3)
      expect((screen.getByRole('button', { name: '重试' }) as HTMLButtonElement).disabled).toBe(true)
    })

    await act(async () => {
      retryIdentities.resolve(jsonResponse({ items: [{
        provider: 'google', provider_name: 'Google', email: 'new@example.test', linked_at: '2026-08-23T00:00:00Z',
      }] }))
      retryProviders.resolve(jsonResponse([{ slug: 'google', name: 'Google' }]))
      await Promise.all([retryIdentities.promise, retryProviders.promise])
    })
    expect(await screen.findByText('new@example.test')).toBeTruthy()
    expect(screen.queryByRole('button', { name: '重试' })).toBeNull()

    await act(async () => {
      staleIdentities.resolve(jsonResponse({ items: [{
        provider: 'github', provider_name: 'GitHub', email: 'old@example.test', linked_at: '2026-08-22T00:00:00Z',
      }] }))
      staleProviders.resolve(jsonResponse({ code: 'stale_failure' }, 503))
      await Promise.all([staleIdentities.promise, staleProviders.promise])
    })

    expect(screen.getByText('new@example.test')).toBeTruthy()
    expect(screen.queryByText('old@example.test')).toBeNull()
    expect(screen.queryByText(/服务暂时不可用/)).toBeNull()
    expect(onNotice).not.toHaveBeenCalled()
  })

  it('卸载后废弃在途加载，不再写入父级 notice', async () => {
    const identities = deferred<Response>()
    const providers = deferred<Response>()
    vi.stubGlobal('fetch', (path: string) => {
      if (path === '/api/v1/auth/external-identities') return identities.promise
      if (path === '/api/v1/auth/external-providers') return providers.promise
      return Promise.reject(new Error(`unexpected request: ${path}`))
    })

    const { onNotice, unmount } = renderBindings()
    unmount()
    await act(async () => {
      identities.resolve(jsonResponse({ code: 'stale_identity_failure' }, 503))
      providers.resolve(jsonResponse({ code: 'stale_provider_failure' }, 503))
      await Promise.all([identities.promise, providers.promise])
    })

    expect(onNotice).not.toHaveBeenCalled()
  })
})
