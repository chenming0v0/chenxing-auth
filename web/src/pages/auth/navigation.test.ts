import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { HISTORY_INDEX, NAVIGATION_EVENT, navigate, replaceUrl } from '../../router'
import { dropDeadRequestId } from './navigation'

describe('dropDeadRequestId', () => {
  beforeEach(() => {
    replaceUrl('/login')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('cleans query parameters without creating a history entry or a fake popstate', () => {
    navigate('/login?request_id=dead&returnTo=%2Foauth%2Fconsent%3Frequest_id%3Ddead')
    const currentIndex = window.history.state?.[HISTORY_INDEX]
    const replaceState = vi.spyOn(window.history, 'replaceState')
    const dispatchEvent = vi.spyOn(window, 'dispatchEvent')

    dropDeadRequestId('dead')

    expect(window.location.href).toContain('/login?returnTo=%2Foauth%2Fconsent')
    expect(window.location.search).not.toContain('request_id=dead')
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: currentIndex }),
      '',
      '/login?returnTo=%2Foauth%2Fconsent',
    )
    expect(dispatchEvent.mock.calls.some(([event]) => event.type === 'popstate')).toBe(false)
    expect(dispatchEvent.mock.calls.some(([event]) => event.type === NAVIGATION_EVENT)).toBe(true)
  })
})
