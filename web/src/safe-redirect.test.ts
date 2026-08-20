import { describe, expect, it } from 'vitest'
import { safeRedirectTarget } from './safe-redirect'

describe('safeRedirectTarget', () => {
  it('allows http and https URLs', () => {
    expect(safeRedirectTarget('https://provider.example/authorize?client_id=1')).toBe(
      'https://provider.example/authorize?client_id=1',
    )
    expect(safeRedirectTarget('http://localhost:8080/callback')).toBe('http://localhost:8080/callback')
  })

  it('rejects javascript: and data: schemes', () => {
    expect(safeRedirectTarget('javascript:alert(1)')).toBeNull()
    expect(safeRedirectTarget('JAVASCRIPT:alert(1)')).toBeNull()
    expect(safeRedirectTarget('  javascript:alert(1)  ')).toBeNull()
    expect(safeRedirectTarget('data:text/html,hello')).toBeNull()
    expect(safeRedirectTarget('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==')).toBeNull()
  })

  it('rejects empty, blank, and malformed URLs', () => {
    expect(safeRedirectTarget('')).toBeNull()
    expect(safeRedirectTarget('   ')).toBeNull()
    expect(safeRedirectTarget('http://[')).toBeNull()
    expect(safeRedirectTarget('https://exa mple.com')).toBeNull()
  })

  it('rejects non-http schemes even when they parse', () => {
    expect(safeRedirectTarget('file:///etc/passwd')).toBeNull()
    expect(safeRedirectTarget('blob:https://example.com/uuid')).toBeNull()
    expect(safeRedirectTarget('vbscript:msgbox(1)')).toBeNull()
  })
})
