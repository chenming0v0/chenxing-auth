import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, fireEvent, waitFor } from '@testing-library/react'
import { AuthPage } from './auth'
import { installCsrfCookie } from '../test/csrf-cookie'
import type { UserMe } from '../api'

/**
 * #685：登录页与注册页之间的切换入口曾把目标写死为 `/register` / `/login`，
 * 待授权上下文（`request_id`、`returnTo`）在切换时丢失，用户从 OAuth 流程进入
 * 登录页后改走注册，注册完成回登录时 requestId 为 null，不再绑定原授权请求，
 * 最终落到 `/console`，第三方授权流程静默断链。
 *
 * 本文件覆盖三条切换路径与恶意 returnTo 的归一化。页面级用例放独立文件，
 * 避免 auth.test.tsx 越过行数上限（与 auth-registration-status.test.tsx 同因）。
 */

// 注册提交是走 apiFetch 的状态变更请求，需要 CSRF cookie 才能发出。
installCsrfCookie()

const authStub = vi.hoisted(() => ({
  profile: null as UserMe | null,
}))

vi.mock('../auth-state', () => ({
  useAuth: () => ({
    user: null,
    status: 'unauthenticated',
    bootstrap: 'ready',
    refresh: () => Promise.resolve(authStub.profile),
    clear: () => {},
    logout: () => Promise.resolve(),
  }),
}))

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  window.history.replaceState({}, '', '/login')
  vi.stubGlobal('fetch', (path: string) => {
    if (path === '/api/v1/auth/registration-status') {
      return Promise.resolve(jsonResponse({ enabled: true, email_verification_required: false, invitation_code_required: false }))
    }
    return Promise.resolve(jsonResponse({ expires_at: '2099-01-01T00:00:00Z' }))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

/** 页面上所有指向目标路径的切换入口：顶栏 CTA 与表单底部链接。 */
function switchHrefs(path: '/login' | '/register'): string[] {
  return screen.getAllByRole('link')
    .map((link) => link.getAttribute('href') ?? '')
    .filter((href) => href.startsWith(path))
}

function queryOf(href: string): URLSearchParams {
  const index = href.indexOf('?')
  return new URLSearchParams(index < 0 ? '' : href.slice(index))
}

function fillRegisterForm() {
  fireEvent.change(screen.getByLabelText('用户名'), { target: { value: 'chenxing_user' } })
  fireEvent.change(screen.getByLabelText('邮箱'), { target: { value: 'user@chenxing.star' } })
  fireEvent.change(screen.getByLabelText('密码'), { target: { value: 'sufficiently-long-pass' } })
}

describe('AuthPage 认证模式切换保留待授权上下文（#685）', () => {
  const PENDING_RETURN_TO = '/oauth/consent?request_id=req-1'

  it('登录 → 注册：顶栏与底部入口都带上 request_id 与编码后的 returnTo', () => {
    window.history.replaceState({}, '', `/login?request_id=req-1&returnTo=${encodeURIComponent(PENDING_RETURN_TO)}`)
    render(<AuthPage mode="login" />)

    const hrefs = switchHrefs('/register')
    expect(hrefs.length).toBeGreaterThanOrEqual(2)
    for (const href of hrefs) {
      expect(queryOf(href).get('request_id')).toBe('req-1')
      expect(queryOf(href).get('returnTo')).toBe(PENDING_RETURN_TO)
      // returnTo 整体编码，其内层 query 不得泄成外层参数
      expect(href).toContain(`returnTo=${encodeURIComponent(PENDING_RETURN_TO)}`)
    }
  })

  it('注册 → 登录：同样保留 request_id 与 returnTo', async () => {
    window.history.replaceState({}, '', `/register?request_id=req-1&returnTo=${encodeURIComponent(PENDING_RETURN_TO)}`)
    render(<AuthPage mode="register" />)
    await screen.findByRole('button', { name: /创建通行证/ })

    const hrefs = switchHrefs('/login')
    expect(hrefs.length).toBeGreaterThanOrEqual(2)
    for (const href of hrefs) {
      expect(queryOf(href).get('request_id')).toBe('req-1')
      expect(queryOf(href).get('returnTo')).toBe(PENDING_RETURN_TO)
    }
  })

  it('切换时丢弃白名单之外的一次性参数', () => {
    window.history.replaceState({}, '', '/login?request_id=req-1&registered=1&logout=failed&external_error=oauth_state_invalid')
    render(<AuthPage mode="login" />)

    for (const href of switchHrefs('/register')) {
      expect([...queryOf(href).keys()]).toEqual(['request_id'])
    }
  })

  it('注册成功回登录：保留待授权上下文并追加 registered=1', async () => {
    window.history.replaceState({}, '', `/register?request_id=req-1&returnTo=${encodeURIComponent(PENDING_RETURN_TO)}`)
    render(<AuthPage mode="register" />)
    await screen.findByRole('button', { name: /创建通行证/ })
    fillRegisterForm()
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByRole('button', { name: /创建通行证/ }))

    await waitFor(() => expect(window.location.pathname).toBe('/login'))
    const params = new URLSearchParams(window.location.search)
    expect(params.get('request_id')).toBe('req-1')
    expect(params.get('returnTo')).toBe(PENDING_RETURN_TO)
    expect(params.get('registered')).toBe('1')
  })

  it.each([
    '//evil.com/x',
    'https://evil.com',
  ])('恶意 returnTo 在切换后被归一化为 /console：%s', (hostile) => {
    window.history.replaceState({}, '', `/login?returnTo=${encodeURIComponent(hostile)}`)
    render(<AuthPage mode="login" />)

    const hrefs = switchHrefs('/register')
    expect(hrefs.length).toBeGreaterThanOrEqual(2)
    for (const href of hrefs) {
      expect(queryOf(href).get('returnTo')).toBe('/console')
      expect(href).not.toContain('evil.com')
    }
  })
})
