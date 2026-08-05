import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import type { PublicExternalProvider } from '../../api'
import { ExternalProviders } from './external-providers'

const mockProviders: PublicExternalProvider[] = [
  { slug: 'github', name: 'GitHub' },
  { slug: 'google', name: 'Google Workspace' },
]

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(() =>
    Promise.resolve({
      ok: true,
      status: 200,
      json: async () => mockProviders,
    } as Response),
  ))
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('ExternalProviders', () => {
  it('renders provider buttons when the list loads successfully', async () => {
    render(<ExternalProviders requestId={null} />)
    expect(screen.getByText('正在加载外部身份源…')).toBeTruthy()
    await waitFor(() => {
      expect(screen.getByText('GitHub')).toBeTruthy()
      expect(screen.getByText('Google Workspace')).toBeTruthy()
    })
  })

  it('appends request_id to the external login URL when provided', async () => {
    render(<ExternalProviders requestId="req-123" />)
    await waitFor(() => {
      const anchor = screen.getByTestId('external-provider-github')
      expect(anchor.getAttribute('href')).toBe('/auth/external/github?request_id=req-123')
    })
  })

  it('shows an empty-state notice when the provider list is empty', async () => {
    vi.stubGlobal('fetch', vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: async () => [],
      } as Response),
    ))
    render(<ExternalProviders requestId={null} />)
    await waitFor(() => {
      expect(screen.getByText('管理员尚未启用任何外部身份源，请使用账号登录。')).toBeTruthy()
    })
  })

  it('shows an error notice and retry button when the fetch fails', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.reject(new Error('network error'))))
    render(<ExternalProviders requestId={null} />)
    await waitFor(() => {
      expect(screen.getByText('外部身份源加载失败，请检查网络后重试。')).toBeTruthy()
      expect(screen.getByText('重新加载')).toBeTruthy()
    })
  })

  it('filters out invalid provider entries', async () => {
    vi.stubGlobal('fetch', vi.fn(() =>
      Promise.resolve({
        ok: true,
        status: 200,
        json: async () => [
          { slug: 'github', name: 'GitHub' },
          { slug: '', name: 'Empty Slug' },
          { slug: 'valid', name: '' },
          null,
        ],
      } as Response),
    ))
    render(<ExternalProviders requestId={null} />)
    await waitFor(() => {
      expect(screen.getByText('GitHub')).toBeTruthy()
      expect(screen.queryByText('Empty Slug')).toBeNull()
      expect(screen.queryByText('valid')).toBeNull()
    })
  })
})
