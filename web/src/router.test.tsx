import { useEffect, useState } from 'react'
import { act, cleanup, render, screen, fireEvent } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  HISTORY_INDEX,
  NAVIGATION_EVENT,
  navigate,
  replaceUrl,
  setNavigationBlocker,
  usePathname,
} from './router'

function waitForPopstates(count: number): Promise<void> {
  return new Promise((resolve) => {
    let seen = 0
    const onPopstate = () => {
      seen += 1
      if (seen < count) return
      window.removeEventListener('popstate', onPopstate)
      resolve()
    }
    window.addEventListener('popstate', onPopstate)
  })
}

/** 在 act 内触发一次 traversal 并等到全部 popstate（含守卫回滚）落地。 */
async function traverse(delta: number, expectedPopstates: number): Promise<void> {
  await act(async () => {
    const settled = waitForPopstates(expectedPopstates)
    window.history.go(delta)
    await settled
  })
}

describe('SPA history navigation', () => {
  beforeEach(() => {
    setNavigationBlocker(null)
    window.history.replaceState({}, '', '/')
  })

  afterEach(() => {
    setNavigationBlocker(null)
    cleanup()
    vi.restoreAllMocks()
  })

  it('keeps one index across multi-step navigation and same-document replacement', () => {
    const popstate = vi.fn()
    const navigation = vi.fn()
    window.addEventListener('popstate', popstate)
    window.addEventListener(NAVIGATION_EVENT, navigation)

    navigate('/one')
    const firstIndex = window.history.state?.[HISTORY_INDEX]
    navigate('/two')
    const secondIndex = window.history.state?.[HISTORY_INDEX]

    expect(firstIndex).toEqual(expect.any(Number))
    expect(secondIndex).toBe((firstIndex as number) + 1)
    expect(popstate).not.toHaveBeenCalled()
    expect(navigation).toHaveBeenCalledTimes(2)

    replaceUrl('/two?tab=security')
    expect(window.location.pathname).toBe('/two')
    expect(window.location.search).toBe('?tab=security')
    expect(window.history.state?.[HISTORY_INDEX]).toBe(secondIndex)
    expect(popstate).not.toHaveBeenCalled()
    expect(navigation).toHaveBeenCalledTimes(3)

    window.removeEventListener('popstate', popstate)
    window.removeEventListener(NAVIGATION_EVENT, navigation)
  })

  it('restores a rejected multi-step Back without corrupting the current index', async () => {
    navigate('/one')
    navigate('/two')
    navigate('/three')
    const currentIndex = window.history.state?.[HISTORY_INDEX] as number
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))

    const settled = waitForPopstates(2)
    window.history.go(-2)
    await settled

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(window.location.pathname).toBe('/three')
    expect(window.history.state?.[HISTORY_INDEX]).toBe(currentIndex)
  })

  it('restores a rejected multi-step Forward without corrupting the current index', async () => {
    navigate('/one')
    navigate('/two')
    navigate('/three')

    const back = waitForPopstates(1)
    window.history.go(-2)
    await back
    const currentIndex = window.history.state?.[HISTORY_INDEX] as number
    expect(window.location.pathname).toBe('/one')

    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))
    const settled = waitForPopstates(2)
    window.history.go(2)
    await settled

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(window.location.pathname).toBe('/one')
    expect(window.history.state?.[HISTORY_INDEX]).toBe(currentIndex)
  })

  it('accepts multi-step Back and Forward with the matching history indices', async () => {
    navigate('/one')
    navigate('/two')
    navigate('/three')
    const currentIndex = window.history.state?.[HISTORY_INDEX] as number
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    setNavigationBlocker(() => window.confirm('leave?'))

    const back = waitForPopstates(1)
    window.history.go(-2)
    await back
    expect(window.location.pathname).toBe('/one')
    expect(window.history.state?.[HISTORY_INDEX]).toBe(currentIndex - 2)

    const forward = waitForPopstates(1)
    window.history.go(2)
    await forward
    expect(window.location.pathname).toBe('/three')
    expect(window.history.state?.[HISTORY_INDEX]).toBe(currentIndex)
    expect(confirm).toHaveBeenCalledTimes(2)
  })

  it('does not ask the dirty blocker for URL cleanup or a 401 replacement', () => {
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))

    replaceUrl('/login?returnTo=%2Fconsole')

    expect(confirm).not.toHaveBeenCalled()
    expect(window.location.pathname).toBe('/login')
    expect(window.location.search).toBe('?returnTo=%2Fconsole')
  })
})

/**
 * #686 的验收：被拒绝的后退不能卸载设置页。
 *
 * 只断言最终 URL 是不够的——#622 的实现最终 URL 也对，但原 popstate 已经先让
 * React 切到目标路由、把带草稿的面板卸载了。这里直接对组件实例的挂载/清理
 * 次数计数，草稿存活与否由「实例是否还是同一个」决定。
 */
describe('拒绝浏览器后退不卸载带草稿的页面（#686）', () => {
  /** 每个实例的生命周期计数，实例编号单调递增，重挂即可见。 */
  const lifecycle = { mounts: 0, cleanups: 0 }

  function DraftSettings() {
    const [instance] = useState(() => (lifecycle.mounts += 1))
    const [draft, setDraft] = useState('')
    useEffect(() => () => { lifecycle.cleanups += 1 }, [])
    return (
      <input
        aria-label="SMTP 服务器"
        data-testid="draft-input"
        data-instance={instance}
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
      />
    )
  }

  function RoutedApp() {
    const path = usePathname()
    return path === '/admin/settings' ? <DraftSettings /> : <div data-testid="other-page">{path}</div>
  }

  /** 进入设置页、渲染、写入草稿，并注册拒绝离开的守卫。 */
  function renderSettingsWithDraft() {
    navigate('/admin/users')
    navigate('/admin/settings')
    render(<RoutedApp />)
    fireEvent.change(screen.getByTestId('draft-input'), { target: { value: 'smtp.example.com' } })
    expect((screen.getByTestId('draft-input') as HTMLInputElement).value).toBe('smtp.example.com')
    expect(lifecycle.mounts).toBe(1)
  }

  beforeEach(() => {
    setNavigationBlocker(null)
    lifecycle.mounts = 0
    lifecycle.cleanups = 0
    window.history.replaceState({}, '', '/')
  })

  afterEach(() => {
    setNavigationBlocker(null)
    cleanup()
    vi.restoreAllMocks()
  })

  it('keeps the same settings instance mounted and the draft intact when Back is declined', async () => {
    renderSettingsWithDraft()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))

    // 拒绝的后退：目标条目的 popstate + 路由器回滚的 popstate。
    await traverse(-1, 2)

    expect(confirm).toHaveBeenCalledTimes(1)
    // 设置页组件实例从未被卸载，也从未被重新挂载。
    expect(lifecycle.cleanups).toBe(0)
    expect(lifecycle.mounts).toBe(1)
    expect(screen.queryByTestId('other-page')).toBeNull()
    const input = screen.getByTestId('draft-input') as HTMLInputElement
    expect(input.dataset.instance).toBe('1')
    expect(input.value).toBe('smtp.example.com')
    expect(window.location.pathname).toBe('/admin/settings')
  })

  it('keeps the settings instance mounted when a multi-step Back is declined', async () => {
    navigate('/console')
    renderSettingsWithDraft()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))

    await traverse(-2, 2)

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(lifecycle.cleanups).toBe(0)
    expect(lifecycle.mounts).toBe(1)
    expect((screen.getByTestId('draft-input') as HTMLInputElement).value).toBe('smtp.example.com')
    expect(window.location.pathname).toBe('/admin/settings')
  })

  it('unmounts the settings page once Back is accepted', async () => {
    renderSettingsWithDraft()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(true)
    setNavigationBlocker(() => window.confirm('leave?'))

    await traverse(-1, 1)

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(lifecycle.cleanups).toBe(1)
    expect(lifecycle.mounts).toBe(1)
    expect(screen.getByTestId('other-page').textContent).toBe('/admin/users')
    expect(window.location.pathname).toBe('/admin/users')
  })

  it('renders the declined page again only when the user goes back on purpose', async () => {
    renderSettingsWithDraft()
    const confirm = vi.spyOn(window, 'confirm').mockReturnValue(false)
    setNavigationBlocker(() => window.confirm('leave?'))
    await traverse(-1, 2)
    expect(lifecycle.mounts).toBe(1)

    // 用户保存或放弃草稿后守卫解除，同一次后退现在必须真正生效。
    setNavigationBlocker(null)
    await traverse(-1, 1)

    expect(confirm).toHaveBeenCalledTimes(1)
    expect(window.location.pathname).toBe('/admin/users')
    expect(screen.getByTestId('other-page').textContent).toBe('/admin/users')
    expect(lifecycle.cleanups).toBe(1)
  })
})
