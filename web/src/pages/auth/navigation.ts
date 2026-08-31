import { replaceUrl } from '../../router'

const DEFAULT_RETURN_TO = '/console'

export function safeReturnTo(value: string | null): string {
  if (!value) return DEFAULT_RETURN_TO
  try {
    decodeURIComponent(value)
    const target = new URL(value.replace(/\\/g, '/'), window.location.origin)
    if (target.origin !== window.location.origin || target.username || target.password) return DEFAULT_RETURN_TO
    return `${target.pathname}${target.search}${target.hash}`
  } catch {
    return DEFAULT_RETURN_TO
  }
}

/**
 * 认证模式切换（登录 ⇄ 注册、注册成功回登录）的目标地址构造。
 *
 * #685：切换入口曾把目标写死成 `/register` / `/login`，OAuth 待授权上下文
 * （`request_id` 与 `returnTo`）在切换时被丢弃，注册完成后 requestId 为 null，
 * 不再绑定原待授权请求，第三方授权流程静默断链。
 *
 * 透传规则是**白名单**而非黑名单：只有 `request_id` 与 `returnTo` 会被带走。
 * 整体搬运查询串等于给开放重定向开一个新入口，而黑名单永远漏掉下一个新增的
 * 一次性参数（`registered`、`logout`、`external_error` 等）。`returnTo` 必须先过
 * `safeReturnTo`，跨 origin / userinfo / 畸形编码的值在此归一化为 `/console`。
 */
export function authModeTarget(
  path: string,
  source: URLSearchParams,
  extra?: Readonly<Record<string, string>>,
): string {
  const params = new URLSearchParams()
  // request_id 是授权请求标识，按普通字符串处理，编码交给 URLSearchParams。
  const requestId = source.get('request_id')
  if (requestId) params.set('request_id', requestId)
  const returnTo = source.get('returnTo')
  if (returnTo) params.set('returnTo', safeReturnTo(returnTo))
  for (const [key, value] of Object.entries(extra ?? {})) params.set(key, value)
  const search = params.toString()
  return search ? `${path}?${search}` : path
}

export function dropDeadRequestId(requestId: string): void {
  const params = new URLSearchParams(window.location.search)
  const returnTo = params.get('returnTo')
  if (returnTo) {
    try {
      const target = new URL(returnTo.replace(/\\/g, '/'), window.location.origin)
      if (target.searchParams.get('request_id') === requestId) {
        target.searchParams.delete('request_id')
        params.set('returnTo', `${target.pathname}${target.search}${target.hash}`)
      }
    } catch {
      // Invalid returnTo remains harmless because safeReturnTo rejects it on navigation.
    }
  }
  if (params.get('request_id') === requestId) params.delete('request_id')
  const hash = window.location.hash
  const search = params.toString()
  const next = `${window.location.pathname}${search ? `?${search}` : ''}${hash}`
  if (next === window.location.pathname + window.location.search + hash) return
  replaceUrl(next)
}
