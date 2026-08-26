import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { installCsrfCookie } from '../../test/csrf-cookie'
import { OAuthProvidersPageBody } from './oauth-providers'

installCsrfCookie()

function jsonResponse(body: unknown, status = 200): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as Response
}

beforeEach(() => {
  vi.stubGlobal('fetch', (path: string) => {
    if (String(path) === '/api/v1/admin/oauth/providers') return Promise.resolve(jsonResponse([]))
    return Promise.resolve(jsonResponse({ code: 'internal' }, 500))
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('身份提供商独立页', () => {
  it('页面标题说明这是 OAuth 2.0 + UserInfo，不是 OIDC', async () => {
    render(<OAuthProvidersPageBody />)
    expect(screen.getByRole('heading', { name: '身份提供商' })).toBeTruthy()
    expect(screen.getByText(/这不是 OIDC/)).toBeTruthy()
    await screen.findByRole('heading', { name: '自定义 OAuth 2.0 提供商' })
    expect(screen.getAllByText(/身份字段只取自 UserInfo 响应，本平台不验证 ID Token/).length).toBeGreaterThan(0)
    expect(screen.getAllByRole('button', { name: '添加 OAuth 提供商' }).length).toBeGreaterThan(0)
  })
})
