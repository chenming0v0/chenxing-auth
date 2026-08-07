import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { ErrorBoundary } from './error-boundary'

// 恢复界面复用 SpaceBackdrop（星野 canvas + matchMedia）与 AuthPanel。
// jsdom 不实现 matchMedia，补一个最小桩；canvas 2d 上下文在 jsdom 返回 null，
// SpaceBackdrop 内部已做空值保护，其余走真实渲染。
function stubMatchMedia() {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: vi.fn().mockReturnValue({
      matches: false,
      media: '',
      onchange: null,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      addListener: vi.fn(),
      removeListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }),
  })
}

const originalLocation = Object.getOwnPropertyDescriptor(window, 'location')

/** 渲染即抛错，用于触发错误边界。错误文案刻意带「机密字样」，供泄漏断言使用。 */
function Bomb() {
  throw new Error('leaked-secret-detail')
}

describe('ErrorBoundary', () => {
  beforeEach(() => {
    stubMatchMedia()
    // 测试环境不走 main.tsx 的 createRoot，React 19 默认 onCaughtError 会把完整
    // 错误打到 console；mock 掉保持输出干净，泄漏断言只检查 UI 渲染内容。
    vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
    if (originalLocation) {
      Object.defineProperty(window, 'location', originalLocation)
    }
  })

  it('renders children normally when nothing throws', () => {
    render(
      <ErrorBoundary>
        <div>正常内容</div>
      </ErrorBoundary>,
    )
    expect(screen.getByText('正常内容')).toBeTruthy()
  })

  it('swaps the crashed tree for the recovery panel', () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    )
    expect(screen.getByRole('heading', { name: '界面遇到问题' })).toBeTruthy()
    expect(screen.queryByText('正常内容')).toBeNull()
  })

  it('does not render error message or stack details', () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    )
    expect(screen.queryByText(/leaked-secret-detail/)).toBeNull()
    expect(screen.queryByText(/at Bomb/i)).toBeNull()
  })

  it('offers a real page reload', () => {
    const reload = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { reload },
    })
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    )
    screen.getByRole('button', { name: '刷新页面' }).click()
    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('offers a plain home link that works without the router', () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    )
    const home = screen.getByRole('link', { name: '返回首页' })
    // 原生锚点走整页导航，不依赖 SPA router 或 App 树状态
    expect(home.getAttribute('href')).toBe('/')
  })

  it('renders the recovery panel through the shared HudPanel container', () => {
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    )
    const heading = screen.getByRole('heading', { name: '界面遇到问题' })
    expect(heading.closest('.chenxing-hud-panel')).toBeTruthy()
  })
})
