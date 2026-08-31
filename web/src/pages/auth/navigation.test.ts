import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { HISTORY_INDEX, NAVIGATION_EVENT, navigate, replaceUrl } from '../../router'
import { authModeTarget, dropDeadRequestId } from './navigation'

describe('authModeTarget（#685）', () => {
  it('把待授权上下文透传到注册页', () => {
    const source = new URLSearchParams('request_id=req-1&returnTo=%2Foauth%2Fconsent%3Frequest_id%3Dreq-1')
    const target = authModeTarget('/register', source)
    const params = new URLSearchParams(target.slice(target.indexOf('?')))

    expect(target.startsWith('/register?')).toBe(true)
    expect(params.get('request_id')).toBe('req-1')
    expect(params.get('returnTo')).toBe('/oauth/consent?request_id=req-1')
    // returnTo 必须以编码形式出现在查询串里，不能把它的 query 泄到外层
    expect(target).toContain('returnTo=%2Foauth%2Fconsent%3Frequest_id%3Dreq-1')
  })

  it('注册成功回登录时在保留上下文的基础上追加 registered=1', () => {
    const source = new URLSearchParams('request_id=req-1&returnTo=%2Foauth%2Fconsent')
    const params = new URLSearchParams(authModeTarget('/login', source, { registered: '1' }).slice('/login'.length + 1))

    expect(params.get('request_id')).toBe('req-1')
    expect(params.get('returnTo')).toBe('/oauth/consent')
    expect(params.get('registered')).toBe('1')
  })

  it('白名单之外的一次性参数一律丢弃', () => {
    const source = new URLSearchParams('request_id=req-1&registered=1&logout=failed&external_error=oauth_state_invalid&next=%2Fadmin')
    const params = new URLSearchParams(authModeTarget('/register', source).slice('/register'.length + 1))

    expect([...params.keys()]).toEqual(['request_id'])
  })

  it('没有上下文时返回裸路径，不留空查询串', () => {
    expect(authModeTarget('/register', new URLSearchParams())).toBe('/register')
    expect(authModeTarget('/login', new URLSearchParams(), { registered: '1' })).toBe('/login?registered=1')
  })

  it.each([
    '//evil.com/x',
    'https://evil.com',
    '/\\evil.com',
  ])('恶意 returnTo 在切换时被 safeReturnTo 归一化为 /console：%s', (hostile) => {
    const source = new URLSearchParams()
    source.set('returnTo', hostile)
    const params = new URLSearchParams(authModeTarget('/register', source).slice('/register'.length + 1))

    expect(params.get('returnTo')).toBe('/console')
    expect(authModeTarget('/register', source)).not.toContain('evil.com')
  })
})

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
