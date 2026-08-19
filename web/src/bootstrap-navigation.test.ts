import { describe, expect, it } from 'vitest'
import { isSpaDocumentNavigation } from './bootstrap-navigation'

describe('isSpaDocumentNavigation', () => {
  const documentNavigation = (path: string) => ({
    method: 'GET',
    path,
    accept: 'text/html,application/xhtml+xml',
    fetchDestination: 'document',
  })

  it.each(['/', '/login', '/bootstrap', '/console', '/oauth/account'])(
    'accepts browser navigation to %s',
    (path) => {
      expect(isSpaDocumentNavigation(documentNavigation(path))).toBe(true)
    },
  )

  it.each([
    '/api/v1/auth/me',
    '/health',
    '/oauth/authorize',
    '/auth/external/github',
    '/.well-known/openid-configuration',
    '/assets/index-ABC12345.js',
    '/favicon.png',
  ])('rejects protocol or asset navigation to %s', (path) => {
    expect(isSpaDocumentNavigation(documentNavigation(path))).toBe(false)
  })

  it('rejects fetches and non-HTML requests', () => {
    expect(isSpaDocumentNavigation({
      ...documentNavigation('/login'),
      fetchDestination: 'empty',
    })).toBe(false)
    expect(isSpaDocumentNavigation({
      ...documentNavigation('/login'),
      accept: 'application/json',
    })).toBe(false)
    expect(isSpaDocumentNavigation({
      ...documentNavigation('/login'),
      method: 'POST',
    })).toBe(false)
  })
})
