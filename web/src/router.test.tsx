import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  HISTORY_INDEX,
  NAVIGATION_EVENT,
  navigate,
  replaceUrl,
  setNavigationBlocker,
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

describe('SPA history navigation', () => {
  beforeEach(() => {
    setNavigationBlocker(null)
    window.history.replaceState({}, '', '/')
  })

  afterEach(() => {
    setNavigationBlocker(null)
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
