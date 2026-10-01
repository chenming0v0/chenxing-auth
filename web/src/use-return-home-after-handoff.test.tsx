/**
 * 交接给应用后切回浏览器：隐藏过一次再可见、或从 bfcache 恢复，就 replace 到 /console；
 * 从没离开过则什么都不做。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, cleanup, renderHook } from '@testing-library/react'
import * as router from './router'
import { useReturnHomeAfterHandoff } from './use-return-home-after-handoff'

function setVisibility(state: DocumentVisibilityState) {
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => state })
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'))
  })
}

function firePageShow(persisted: boolean) {
  const event = new Event('pageshow') as PageTransitionEvent
  Object.defineProperty(event, 'persisted', { value: persisted })
  act(() => {
    window.dispatchEvent(event)
  })
}

beforeEach(() => {
  router.replaceUrl('/oauth/consent')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
  // 恢复 jsdom 原生 getter（原型上的那个）
  delete (document as { visibilityState?: unknown }).visibilityState
  router.replaceUrl('/')
})

describe('useReturnHomeAfterHandoff', () => {
  it('隐藏后再可见：replace 导航到 /console，不新增历史条目', () => {
    const spy = vi.spyOn(router, 'navigate')
    const lengthBefore = window.history.length
    renderHook(() => useReturnHomeAfterHandoff())

    setVisibility('hidden')
    expect(spy).not.toHaveBeenCalled()
    setVisibility('visible')

    expect(spy).toHaveBeenCalledTimes(1)
    expect(spy).toHaveBeenCalledWith('/console', { replace: true })
    expect(window.location.pathname).toBe('/console')
    expect(window.history.length).toBe(lengthBefore)
  })

  it('从没隐藏过：可见事件不触发导航', () => {
    const spy = vi.spyOn(router, 'navigate')
    renderHook(() => useReturnHomeAfterHandoff())

    setVisibility('visible')
    setVisibility('visible')

    expect(spy).not.toHaveBeenCalled()
    expect(window.location.pathname).toBe('/oauth/consent')
  })

  it('pageshow persisted（bfcache 恢复）触发同样的导航', () => {
    const spy = vi.spyOn(router, 'navigate')
    renderHook(() => useReturnHomeAfterHandoff())

    firePageShow(true)

    expect(spy).toHaveBeenCalledWith('/console', { replace: true })
    expect(window.location.pathname).toBe('/console')
  })

  it('pageshow 非 persisted（首次加载）不触发导航', () => {
    const spy = vi.spyOn(router, 'navigate')
    renderHook(() => useReturnHomeAfterHandoff())

    firePageShow(false)

    expect(spy).not.toHaveBeenCalled()
  })

  it('enabled=false 时不注册监听', () => {
    const spy = vi.spyOn(router, 'navigate')
    renderHook(() => useReturnHomeAfterHandoff(false))

    setVisibility('hidden')
    setVisibility('visible')
    firePageShow(true)

    expect(spy).not.toHaveBeenCalled()
  })

  it('卸载时移除监听', () => {
    const docRemove = vi.spyOn(document, 'removeEventListener')
    const winRemove = vi.spyOn(window, 'removeEventListener')
    const spy = vi.spyOn(router, 'navigate')
    const view = renderHook(() => useReturnHomeAfterHandoff())

    view.unmount()

    expect(docRemove).toHaveBeenCalledWith('visibilitychange', expect.any(Function))
    expect(winRemove).toHaveBeenCalledWith('pageshow', expect.any(Function))
    setVisibility('hidden')
    setVisibility('visible')
    firePageShow(true)
    expect(spy).not.toHaveBeenCalled()
  })
})
