/** api.ts 的 CSRF token 解析和错误文案映射测试。 */
import { describe, expect, it } from 'vitest'
import { externalLoginErrorMessage, parseCsrfToken, safeErrorMessage } from './api'

const SAFE_FALLBACK = '请求未完成，请稍后重试。'
/** Object.prototype 上真实存在的成员；对象字面量查表时它们会返回 Function/Object。 */
const POLLUTION_KEYS = [
  'constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty',
  'isPrototypeOf', 'propertyIsEnumerable', 'toLocaleString',
]

describe('parseCsrfToken', () => {
  it('reads the secure host-only cookie name', () => {
    expect(parseCsrfToken('__Host-chenxing_csrf=abc123')).toBe('abc123')
  })

  it('reads the token from a single cookie', () => {
    expect(parseCsrfToken('chenxing_csrf=abc123')).toBe('abc123')
  })

  it('reads the token from a cookie list regardless of position', () => {
    expect(parseCsrfToken('a=1; chenxing_csrf=abc123; b=2')).toBe('abc123')
    expect(parseCsrfToken('chenxing_csrf=abc123; b=2')).toBe('abc123')
    expect(parseCsrfToken('a=1; chenxing_csrf=abc123')).toBe('abc123')
    expect(parseCsrfToken('a=1; __Host-chenxing_csrf=abc123; b=2')).toBe('abc123')
  })

  it('tolerates missing spaces and extra whitespace between cookies', () => {
    expect(parseCsrfToken('a=1;chenxing_csrf=abc123;b=2')).toBe('abc123')
    expect(parseCsrfToken('a=1;    chenxing_csrf=abc123')).toBe('abc123')
  })

  it('decodes percent-encoded token values', () => {
    expect(parseCsrfToken('chenxing_csrf=a%2Bb%3Dc')).toBe('a+b=c')
  })

  it('falls back to the raw value when percent-decoding fails', () => {
    // 畸形编码不应让整个请求链路抛异常，原样返回由后端拒绝。
    expect(parseCsrfToken('chenxing_csrf=%E0%A4%A')).toBe('%E0%A4%A')
    expect(parseCsrfToken('chenxing_csrf=100%')).toBe('100%')
  })

  it('returns undefined when the cookie is absent or empty', () => {
    expect(parseCsrfToken('')).toBeUndefined()
    expect(parseCsrfToken('a=1; b=2')).toBeUndefined()
    expect(parseCsrfToken('chenxing_csrf=')).toBeUndefined()
    expect(parseCsrfToken('a=1; chenxing_csrf=; b=2')).toBeUndefined()
  })

  it('does not match cookies that merely contain the name', () => {
    // 前缀匹配必须锚定在 cookie 名开头，否则攻击者可用 x_chenxing_csrf 顶替。
    expect(parseCsrfToken('not_chenxing_csrf=evil')).toBeUndefined()
    expect(parseCsrfToken('xchenxing_csrf=evil')).toBeUndefined()
    expect(parseCsrfToken('other=chenxing_csrf=evil')).toBeUndefined()
  })

  it('picks the first matching cookie when duplicates exist', () => {
    expect(parseCsrfToken('chenxing_csrf=first; chenxing_csrf=second')).toBe('first')
  })

  it('prefers the secure cookie when both names are present', () => {
    expect(parseCsrfToken('chenxing_csrf=local; __Host-chenxing_csrf=secure')).toBe('secure')
  })
})

describe('safeErrorMessage', () => {
  it('prefers the mapped message for known codes', () => {
    expect(safeErrorMessage(401, 'invalid_credentials')).toBe('账号或密码不正确。')
    expect(safeErrorMessage(400, 'passkey_disabled')).toBe('Passkey 登录尚未启用。')
    expect(safeErrorMessage(404, 'invitation_code_not_found')).toBe('邀请码不存在或已失效。')
    expect(safeErrorMessage(500, 'csrf_invalid')).toBe('请求校验失败，请刷新页面后重试。')
  })

  it('falls back to status text for unknown or missing codes', () => {
    expect(safeErrorMessage(400)).toBe('请求参数不正确，请检查输入。')
    expect(safeErrorMessage(401)).toBe('登录状态已失效，请重新登录。')
    expect(safeErrorMessage(403)).toBe('当前账号没有执行此操作的权限。')
    expect(safeErrorMessage(404)).toBe('请求的资源不存在或已失效。')
    expect(safeErrorMessage(409)).toBe('请求与当前数据冲突，请刷新后重试。')
    expect(safeErrorMessage(429)).toBe('操作过于频繁，请稍后重试。')
    expect(safeErrorMessage(500)).toBe('服务暂时不可用，请稍后重试。')
    expect(safeErrorMessage(503)).toBe('服务暂时不可用，请稍后重试。')
    expect(safeErrorMessage(418)).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(0)).toBe(SAFE_FALLBACK)
  })

  it('ignores unknown codes instead of echoing them', () => {
    // 错误码来自后端响应体，不能被当作文案拼进界面。
    expect(safeErrorMessage(400, 'sql_error_at_users_table')).toBe('请求参数不正确，请检查输入。')
    expect(safeErrorMessage(200, 'totally_unknown_code')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(400, '')).toBe('请求参数不正确，请检查输入。')
  })

  it('returns a safe string for prototype keys (regression for #97)', () => {
    // 查表改成 Map 之前，'constructor' 会返回 Object 构造函数，React 渲染它会整页崩溃。
    for (const code of POLLUTION_KEYS) {
      const message = safeErrorMessage(500, code)
      expect(typeof message).toBe('string')
      expect(typeof message).not.toBe('function')
      expect(message).toBe('服务暂时不可用，请稍后重试。')
    }
    expect(safeErrorMessage(200, 'constructor')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(200, '__proto__')).toBe(SAFE_FALLBACK)
    expect(safeErrorMessage(200, 'toString')).toBe(SAFE_FALLBACK)
  })
})

describe('externalLoginErrorMessage', () => {
  it('maps known codes and defaults the rest', () => {
    expect(externalLoginErrorMessage('oauth_provider_not_found')).toBe('该外部身份源不可用或已被停用。')
    expect(externalLoginErrorMessage('oauth_login_rate_limited')).toBe('外部登录尝试过于频繁，请稍后重试。')
    expect(externalLoginErrorMessage('whatever')).toBe('外部身份源登录未完成，请重试。')
    expect(externalLoginErrorMessage('')).toBe('外部身份源登录未完成，请重试。')
  })

  it('returns a safe string for prototype keys (regression for #97)', () => {
    // 该 code 直接来自 URL 查询参数，是 #97 最容易被外部触达的入口。
    for (const code of POLLUTION_KEYS) {
      const message = externalLoginErrorMessage(code)
      expect(typeof message).toBe('string')
      expect(message).toBe('外部身份源登录未完成，请重试。')
    }
  })
})
