import { afterEach, beforeEach } from 'vitest'

/**
 * 需要 CSRF 的测试文件显式调用本函数（放在文件顶层），其余测试不带任何 CSRF Cookie。
 *
 * 曾在 setup.ts 全局注入 CSRF Cookie 的做法已废弃（#374）：它让每个测试都隐式携带
 * 有效 token，导致 api.ts 的「无 cookie → csrf_required」分支在整个套件里无法被测，
 * 也把所有测试固化在 chenxing_csrf 回退名上。beforeEach 注入 + afterEach 对称清理，
 * 保证用例之间互不残留。
 */
export function installCsrfCookie(): void {
  beforeEach(() => {
    document.cookie = 'chenxing_csrf=test-csrf-token; path=/'
  })
  afterEach(() => {
    // __Host- 前缀要求 Secure 属性，缺了它 tough-cookie 会静默丢弃，清不掉残留。
    document.cookie = '__Host-chenxing_csrf=; Secure; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
    document.cookie = 'chenxing_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
  })
}
