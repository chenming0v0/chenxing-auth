import { describe, expect, it } from 'vitest'
import { validatePasskeyOrigins } from './passkey-panel'

/* Issue #396：allowed_origins 前端校验，规则对齐服务端
   `PasskeySetting::validate` + `normalize_origins`（src/settings/domain.rs）。 */

const RP_ID = 'auth.clya.top'

describe('validatePasskeyOrigins', () => {
  it('accepts https origins whose host equals the rp_id or is a subdomain', () => {
    expect(validatePasskeyOrigins('https://auth.clya.top, https://app.auth.clya.top', RP_ID, false)).toEqual({
      origins: ['https://auth.clya.top', 'https://app.auth.clya.top'],
    })
    expect(validatePasskeyOrigins('https://api.auth.clya.top:8443 https://auth.clya.top', RP_ID, false)).toEqual({
      origins: ['https://api.auth.clya.top:8443', 'https://auth.clya.top'],
    })
  })

  it('matches hosts case-insensitively, like the server does', () => {
    expect(validatePasskeyOrigins('HTTPS://AUTH.CLYA.TOP', 'Auth.Clya.Top', false)).toEqual({
      origins: ['HTTPS://AUTH.CLYA.TOP'],
    })
  })

  it('allows http only for loopback hosts or when insecure origins are enabled', () => {
    expect(validatePasskeyOrigins('http://localhost:3000', 'localhost', false)).toEqual({
      origins: ['http://localhost:3000'],
    })
    expect(validatePasskeyOrigins('http://127.0.0.1:3000', '127.0.0.1', false)).toEqual({
      origins: ['http://127.0.0.1:3000'],
    })
    expect(validatePasskeyOrigins('http://auth.clya.top', RP_ID, true)).toEqual({
      origins: ['http://auth.clya.top'],
    })
    // 回环只豁免 http 协议，host 归属校验仍然生效（服务端同规则）。
    expect(validatePasskeyOrigins('http://127.0.0.1:3000', 'localhost', false)).toEqual({
      error: '「http://127.0.0.1:3000」的 host 必须等于 RP ID（localhost）或是它的子域。',
    })
    expect(validatePasskeyOrigins('http://auth.clya.top', RP_ID, false)).toEqual({
      error: '「http://auth.clya.top」必须使用 https；http 仅允许 localhost 等本机地址，或开启「允许不安全的 Origin」。',
    })
  })

  it('rejects empty input and too many origins', () => {
    expect(validatePasskeyOrigins('', RP_ID, false)).toEqual({ error: '请至少填写一个 Origin。' })
    const tooMany = Array.from({ length: 33 }, (_, index) => `https://sub${index}.auth.clya.top`).join(' ')
    expect(validatePasskeyOrigins(tooMany, RP_ID, false)).toEqual({
      error: 'Origin 数量不能超过 32 个。',
    })
  })

  it('normalizes and deduplicates before applying the limit', () => {
    const duplicates = Array.from({ length: 33 }, () => 'HTTPS://AUTH.CLYA.TOP').join(' ')
    expect(validatePasskeyOrigins(duplicates, RP_ID, false)).toEqual({ origins: ['https://auth.clya.top'] })
  })


  it('rejects non-URL input, non-origin schemes, and credentials', () => {
    expect(validatePasskeyOrigins('auth.clya.top', RP_ID, false)).toEqual({
      error: '「auth.clya.top」不是合法的 URL，请填写完整 Origin，例如 https://auth.clya.top。',
    })
    // `javascript:` 能解析成 URL，但没有 host，必须按 Origin 形状拒绝。
    expect(validatePasskeyOrigins('javascript:alert(1)', RP_ID, false)).toEqual({
      error: '「javascript:alert(1)」只能是 scheme://host[:port] 形式的 Origin，不能带路径、查询参数或片段。',
    })
    expect(validatePasskeyOrigins('ftp://auth.clya.top', RP_ID, false)).toEqual({
      error: '「ftp://auth.clya.top」必须使用 https；http 仅允许 localhost 等本机地址，或开启「允许不安全的 Origin」。',
    })
    expect(validatePasskeyOrigins('https://user:pass@auth.clya.top', RP_ID, false)).toEqual({
      error: '「https://user:pass@auth.clya.top」不能包含用户名或密码。',
    })
  })

  it('rejects paths, query strings, fragments, and hosts outside the rp_id', () => {
    for (const origin of ['https://auth.clya.top/path', 'https://auth.clya.top?x=1', 'https://auth.clya.top#frag']) {
      expect(validatePasskeyOrigins(origin, RP_ID, false)).toEqual({
        error: `「${origin}」只能是 scheme://host[:port] 形式的 Origin，不能带路径、查询参数或片段。`,
      })
    }
    // 后缀规则不能绕过：notauth.clya.top 不是 auth.clya.top 的子域。
    for (const origin of ['https://evil.com', 'https://notauth.clya.top', 'https://auth.clya.top.']) {
      expect(validatePasskeyOrigins(origin, RP_ID, false)).toEqual({
        error: `「${origin}」的 host 必须等于 RP ID（${RP_ID}）或是它的子域。`,
      })
    }
  })

  it('requires an rp_id before any origin can match', () => {
    expect(validatePasskeyOrigins('https://auth.clya.top', '', false)).toEqual({
      error: '请先填写 RP ID：Origin 的 host 必须等于 RP ID 或是它的子域。',
    })
  })
})
