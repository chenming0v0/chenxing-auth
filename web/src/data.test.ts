import { describe, expect, it } from 'vitest'
import { getDocumentTitle } from './data'

describe('document title routing', () => {
  it('gives the security compatibility route the profile title', () => {
    expect(getDocumentTitle('/settings/security')).toBe('控制台 · 个人信息 · 辰星通行证')
    expect(getDocumentTitle('/settings/security')).toBe(getDocumentTitle('/console/security'))
  })
})
