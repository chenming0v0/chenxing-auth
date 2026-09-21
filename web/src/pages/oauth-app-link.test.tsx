/**
 * oauth-app-link.tsx：移动端 App Link 回调落到浏览器时的兜底页。
 * - 路径匹配只接受精确的 /app/<数字>/oauth/callback。
 * - 进入后立即清掉地址栏里的 code/state/error（#196），但原始完整链接保留在
 *   组件状态里，供用户点击原生 <a> 再次触发 App Link。
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { AppLinkCallbackPage, matchAppLinkCallback } from './oauth-app-link'
import { HISTORY_INDEX } from '../router'

beforeEach(() => {
  window.history.replaceState({}, '', '/')
})

afterEach(() => {
  cleanup()
  vi.restoreAllMocks()
})

describe('matchAppLinkCallback 只接受精确的 App Link 回调路径', () => {
  it('匹配数字 id 的回调路径并返回 id', () => {
    expect(matchAppLinkCallback('/app/1/oauth/callback')).toBe('1')
    expect(matchAppLinkCallback('/app/42/oauth/callback')).toBe('42')
  })

  it('拒绝尾部斜杠、非数字 id 与其他路径', () => {
    expect(matchAppLinkCallback('/app/1/oauth/callback/')).toBeNull()
    expect(matchAppLinkCallback('/app/x/oauth/callback')).toBeNull()
    expect(matchAppLinkCallback('/app/1/oauth')).toBeNull()
    expect(matchAppLinkCallback('/oauth/redirect')).toBeNull()
  })
})

describe('AppLinkCallbackPage 进入时清理敏感 query 并保留原始链接（#196）', () => {
  it('带 code/state 进入：展示成功分支，原生锚点指向原始完整链接，地址栏被清理', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback?code=secret-code&state=xyz')
    const originalHref = window.location.href
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权完成，请返回应用' })).toBeTruthy()
    const anchor = screen.getByRole('link', { name: '打开应用继续' })
    expect(anchor.getAttribute('href')).toBe(originalHref)
    expect(anchor.getAttribute('href')).toContain('code=secret-code')
    expect(anchor.getAttribute('href')).toContain('state=xyz')
    expect(screen.getByRole('link', { name: '返回控制台' }).getAttribute('href')).toBe('/console')
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/app/1/oauth/callback',
    )
  })

  it('带 error 进入：展示错误分支，仍提供返回应用的原生锚点', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback?error=access_denied')
    const originalHref = window.location.href
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权没有完成' })).toBeTruthy()
    expect(screen.getByRole('link', { name: '返回应用' }).getAttribute('href')).toBe(originalHref)
    expect(screen.getByRole('link', { name: '返回控制台' })).toBeTruthy()
    expect(replaceState).toHaveBeenCalledWith(
      expect.objectContaining({ [HISTORY_INDEX]: expect.any(Number) }), '', '/app/1/oauth/callback',
    )
  })

  it('无查询参数进入：判定为无效回调，不改写地址', () => {
    window.history.replaceState({}, '', '/app/1/oauth/callback')
    const replaceState = vi.spyOn(window.history, 'replaceState').mockImplementation(() => {})

    render(<AppLinkCallbackPage />)

    expect(screen.getByRole('heading', { name: '授权回调无效' })).toBeTruthy()
    expect(screen.getByRole('link', { name: '返回控制台' }).getAttribute('href')).toBe('/console')
    expect(screen.queryByRole('link', { name: /应用/ })).toBeNull()
    expect(replaceState).not.toHaveBeenCalled()
  })
})
