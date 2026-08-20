/**
 * 校验后端返回的跳转地址：只允许 http/https。
 *
 * `window.location.assign` 会执行 `javascript:` / `data:` 等伪协议。后端响应一旦被
 * 污染，确认页或外部绑定页就会在应用源下跑攻击者脚本，所以导航前必须解析并检查
 * 协议。空串、空白、缺 host、畸形输入一律视为无效；相对路径按当前 origin 解析，
 * 解析后仍须是 http(s) 且带 host。
 */
export function safeRedirectTarget(raw: string): string | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null
  try {
    const url = new URL(raw.trim(), window.location.origin)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    if (!url.hostname) return null
    return url.href
  } catch {
    return null
  }
}
