import { responseGuard } from './api-response-guards'
import type {
  ApiRequestInit,
  EntitlementsResponse,
  PendingAuthorization,
  UserMe,
} from './api-types'
import { replaceUrl } from './router'

export type * from './api-types'

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

/** 从 cookie 字符串中解析 CSRF token；接受字符串入参以便脱离 document 单测。 */
export function parseCsrfToken(cookieString: string): string | undefined {
  for (const name of ['__Host-chenxing_csrf', 'chenxing_csrf']) {
    const value = cookieString
      .split(';')
      .map((cookie) => cookie.trim())
      .find((cookie) => cookie.startsWith(`${name}=`))
      ?.slice(name.length + 1)
    if (!value) continue
    try {
      return decodeURIComponent(value)
    } catch {
      return value
    }
  }
  return undefined
}

function csrfToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  return parseCsrfToken(document.cookie)
}

const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])
const PRE_SESSION_MUTATION_PATHS = new Set([
  '/api/v1/admin/bootstrap',
  '/api/v1/users',
  '/api/v1/auth/login',
  '/api/v1/auth/totp/setup',
  '/api/v1/auth/totp/setup/confirm',
  '/api/v1/auth/totp/login',
  '/api/v1/auth/passkeys/register/start',
  '/api/v1/auth/passkeys/register/finish',
  '/api/v1/auth/passkeys/authentication/start',
  '/api/v1/auth/passkeys/authentication/finish',
  '/api/v1/auth/passkeys/discoverable/start',
  '/api/v1/auth/passkeys/discoverable/finish',
  '/api/v1/auth/security/factor/enrollment/cancel',
])

/** 安全错误码文案映射，使用 Map 避免原型链污染（Object 字面量索引可访问 constructor 等原型属性）。 */
const safeMessages = new Map<string, string>([
  ['invalid_credentials', '账号或密码不正确。'],
  ['invalid_factor', '验证码不正确，请重试。'],
  ['invalid_passkey', 'Passkey 验证未通过，请重试。'],
  ['invalid_login_ticket', '验证流程已失效，请重新登录。'],
  ['email_already_registered', '注册信息无法使用，请检查后重试。'],
  ['email_domain_not_allowed', '当前邮箱域名不允许注册。'],
  ['passkey_disabled', 'Passkey 登录尚未启用。'],
  ['factor_enrollment_pending', '该认证因子已有待确认操作，请完成当前操作或稍后重试。'],
  ['totp_already_enabled', 'TOTP 已启用，无需重复绑定。'],
  ['factor_already_enabled', '认证因子已启用。'],
  ['invalid_factor_enrollment', '认证因子绑定已失效，请重新开始。'],
  ['password_reauthentication_failed', '当前密码不正确，未执行安全操作。'],
  ['password_reauthentication_unavailable', '当前账号无法使用密码重新认证，请联系管理员恢复。'],
  ['current_password_required', '修改用户名需要输入当前密码。'],
  ['username_unavailable', '该用户名已被占用，请更换后重试。'],
  ['factor_key_unavailable', '服务端暂时无法读取认证密钥，请联系管理员处理。'],
  ['passkey_credential_conflict', '该 Passkey 已在其他账号或设备记录中使用。'],
  ['username_already_registered', '注册信息无法使用，请检查后重试。'],
  ['invalid_username', '用户名格式不正确，请检查长度和字符。'],
  ['invalid_email', '邮箱格式不正确，请检查输入。'],
  ['invitation_code_not_found', '邀请码不存在或已失效。'],
  ['password_too_short', '密码长度不足，请设置更长的密码。'],
  ['password_too_long', '密码超出长度上限，请缩短后重试。'],
  ['display_name_too_long', '显示名称超出长度上限，请缩短后重试。'],
  ['invalid_role', '角色参数不正确，请重新选择。'],
  ['invalid_status', '状态参数不正确，请重新选择。'],
  ['oauth_client_quota_exceeded', '当前套餐的 OAuth 应用额度已用尽。'],
  ['oauth_quota_exceeded', '当前 OAuth 授权额度已用尽。'],
  ['authorization_request_expired', '授权请求已过期，请重新发起。'],
  ['authorization_request_processed', '授权请求已经处理过。'],
  ['authorization_request_conflict', '授权请求正在被其他标签页更新，请稍后重试。'],
  ['authorization_holder_invalid', '这条授权请求不是在当前浏览器发起的，请回到应用重新开始授权。'],
  ['csrf_invalid', '请求校验失败，请刷新页面后重试。'],
  ['csrf_required', '请求校验失败，请刷新页面后重试。'],
  ['invalid_plan', '套餐参数不正确，请检查输入。'],
  ['plan_not_found', '套餐不存在或已失效。'],
  ['insufficient_balance', '辰星点不足，无法购买该套餐。'],
  ['plan_not_purchasable', '该套餐不支持自助购买。'],
  ['invalid_amount', '充值数量不合法。'],
  ['invalid_note', '备注过长。'],
  ['plan_code_conflict', '套餐代码已被占用，请更换。'],
  ['archived_plan_default', '已归档的套餐不能设为默认。'],
  ['self_service_disabled', '平台当前未开放自助接入，请联系管理员。'],
  ['plan_archived', '已归档的套餐不能分配给用户。'],
  ['invalid_expiration', '到期时间格式不正确，请重新选择。'],
  ['oauth_provider_not_found', '该外部身份源不可用或已被停用。'],
  ['invalid_oauth_provider', '外部身份源配置不完整，请检查 Endpoint、Scopes 和 Email Verified Claim。'],
  ['oauth_login_failed', '外部身份源登录未完成，请重试。'],
  ['oauth_login_rate_limited', '外部登录尝试过于频繁，请稍后重试。'],
  ['oauth_request_expired', '授权请求已过期，请重新发起。'],
  ['oauth_request_binding_failed', '授权请求绑定失败，请重新开始。'],
  ['oauth_account_link_required', '该外部账号尚未绑定辰星通行证，请先登录后在账号设置中绑定。'],
  ['oauth_email_unverified', '外部身份源未确认该邮箱已验证，无法用它登录或建号。请先在该身份源完成邮箱验证。'],
  ['avatar_empty', '没有读取到图片内容，请重新选择。'],
  ['avatar_too_large', '图片超出大小上限，请更换一张。'],
  ['avatar_unsupported_format', '只支持 PNG、JPEG 或 WebP 图片。'],
  ['avatar_undecodable', '图片无法读取，请更换一张。'],
  ['avatar_too_small', '图片尺寸过小，请选择更清晰的图片。'],
  ['avatar_not_found', '当前没有设置头像。'],
])

/** 把 HTTP 状态码和后端错误码映射为用户可见文案；返回值恒为 string，不泄露内部细节。 */
export function safeErrorMessage(status: number, code?: string): string {
  const mapped = code ? safeMessages.get(code) : undefined
  if (mapped) return mapped
  if (status === 400) return '请求参数不正确，请检查输入。'
  if (status === 401) return '登录状态已失效，请重新登录。'
  if (status === 403) return '当前账号没有执行此操作的权限。'
  if (status === 404) return '请求的资源不存在或已失效。'
  if (status === 409) return '请求与当前数据冲突，请刷新后重试。'
  if (status === 429) return '操作过于频繁，请稍后重试。'
  if (status >= 500) return '服务暂时不可用，请稍后重试。'
  return '请求未完成，请稍后重试。'
}

/**
 * 构造「登录完成后能接着干原来的事」的登录页地址。
 *
 * OAuth 待授权请求的 `request_id` 必须提升为登录页自己的顶层查询参数（#270）：
 * 登录页只读自己的 `request_id` 来决定登录后是否把新会话绑定到待授权请求。
 * 埋在 `returnTo` 里它读不到，于是登录成功后直接跳回确认页，确认页拿着新会话
 * 撞上旧的会话绑定再次 401，又被送回登录页——这就是 401 登录循环的成因。
 *
 * `returnTo` 照旧保留，非 OAuth 场景的回跳行为不变。
 */
export function loginRecoveryTarget(pathname: string, search: string): string {
  const returnTo = `/login?returnTo=${encodeURIComponent(`${pathname}${search}`)}`
  const requestId = new URLSearchParams(search).get('request_id')
  return requestId ? `${returnTo}&request_id=${encodeURIComponent(requestId)}` : returnTo
}

function redirectToLogin(): void {
  if (typeof window === 'undefined' || window.location.pathname === '/login') return
  const target = loginRecoveryTarget(window.location.pathname, window.location.search)
  replaceUrl(target)
}

function invalidSuccessResponse(status: number): ApiError {
  return new ApiError(safeErrorMessage(status), status)
}

function normalizeMethod(method: RequestInit['method']): string {
  const normalized = String(method ?? 'GET').trim().toUpperCase()
  return normalized || 'GET'
}

function missingCsrfError(): ApiError {
  return new ApiError(safeErrorMessage(0, 'csrf_required'), 0, 'csrf_required')
}

export async function apiFetch<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  const { redirectOn401 = true, csrf = 'required', ...requestInit } = init
  const method = normalizeMethod(requestInit.method)
  const headers = new Headers(requestInit.headers)
  headers.set('Accept', 'application/json')
  if (!SAFE_HTTP_METHODS.has(method)) {
    /* Content-Type 只在调用方没有表态、且 body 不自带类型时才补 JSON。
       FormData 需要 fetch 生成 multipart boundary，Blob 自带 MIME（头像上传即走这条路），
       两者被强改成 application/json 都会让服务端拿到错误的类型声明。 */
    const bodyCarriesOwnType = requestInit.body instanceof FormData || requestInit.body instanceof Blob
    if (!bodyCarriesOwnType && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', token)
    else if (!headers.has('X-CSRF-Token')) {
      const allowedWithoutCsrf = csrf === 'pre-session' && PRE_SESSION_MUTATION_PATHS.has(path)
      if (!allowedWithoutCsrf) throw missingCsrfError()
    }
  }

  let response: Response
  try {
    response = await fetch(path, { ...requestInit, headers, credentials: 'include' })
  } catch {
    throw new ApiError('网络连接不可用，请稍后重试。', 0)
  }

  if (!response.ok) {
    const detail = await response.json().catch(() => null) as { code?: string } | null
    const code = typeof detail?.code === 'string' ? detail.code : undefined
    if (response.status === 401 && redirectOn401) redirectToLogin()
    throw new ApiError(safeErrorMessage(response.status, code), response.status, code)
  }

  const guard = responseGuard(path, method)
  if (response.status === 204) {
    if (guard) throw invalidSuccessResponse(response.status)
    return undefined as T
  }

  let body: unknown
  try {
    body = await response.json()
  } catch {
    throw invalidSuccessResponse(response.status)
  }
  if (body === undefined || (guard && !guard(body))) {
    throw invalidSuccessResponse(response.status)
  }
  return body as T
}

/**
 * 头像字节地址。
 *
 * 该端点按会话返回本人头像，响应体不随路径变化，因此必须把版本时间戳带进查询参数：
 * 否则浏览器会一直复用旧头像的缓存条目，用户换了图也看不到变化。
 */
export function avatarUrl(user: Pick<UserMe, 'avatar_updated_at'> | null | undefined): string | undefined {
  if (!user?.avatar_updated_at) return undefined
  return `/api/v1/auth/me/avatar?v=${encodeURIComponent(user.avatar_updated_at)}`
}

/**
 * 外部登录失败时后端回跳 /login?external_error=<code>，此处复用统一文案表。
 * code 直接来自 URL 查询参数，必须经 Map 查表，避免命中 Object.prototype 上的
 * constructor / toString 等成员导致 React 渲染函数子节点而整页崩溃。
 */
export function externalLoginErrorMessage(code: string): string {
  return safeMessages.get(code) ?? '外部身份源登录未完成，请重试。'
}

function authorizationRequestPath(requestId: string, suffix = ''): string {
  return `/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}${suffix}`
}

/**
 * 把当前会话绑定到待授权请求。服务端语义是幂等的受控重绑：holder Cookie 与
 * CSRF 校验通过时，无论此前绑的是哪个会话摘要，都会绑到当前会话（#270）。
 *
 * `redirectOn401: false`：401 的处置权交给调用方。默认的自动跳登录页会在
 * 「登录成功但绑定失败」时把用户送回登录页，正是要避免的循环。
 */
export function bindAuthorizationRequest(requestId: string): Promise<void> {
  return apiFetch<void>(authorizationRequestPath(requestId, '/bind'), {
    method: 'POST',
    redirectOn401: false,
  })
}

/**
 * 读取授权确认页所需数据，读之前先做一次绑定。
 *
 * 绑定放在前面是为了让「会话过期重登」和「切换账号」自愈：这两种情况下浏览器
 * 持有的是新会话，而 pending 记录还指着旧会话摘要，直接读会 401。先绑再读，
 * 新会话接管请求，读取随即成功。绑定幂等，重复调用没有副作用。
 *
 * 绑定失败不直接抛错：holder 缺失等情形下会话本身可能仍然有效且已绑定，
 * 此时读取能成功，流程不该被拦断。只有读取也失败时才把绑定错误抛出去——
 * 它比读取端的通用 401 更能说明真实原因。
 */
export async function loadAuthorizationRequest(requestId: string): Promise<PendingAuthorization> {
  let bindError: unknown = null
  try {
    await bindAuthorizationRequest(requestId)
  } catch (error) {
    bindError = error
  }
  try {
    return await apiFetch<PendingAuthorization>(authorizationRequestPath(requestId), {
      redirectOn401: false,
    })
  } catch (error) {
    throw bindError ?? error
  }
}

let entitlementCache: EntitlementsResponse | null = null
let entitlementRequest: Promise<EntitlementsResponse> | null = null
/**
 * 缓存版本计数器。clearApiCache()（注销时）和 getEntitlements(force=true) 递增它，
 * 使版本号变化前发出的 in-flight 请求在 resolve 后无法把过期数据写回缓存：
 * 注销场景避免跨用户泄露，强制刷新场景避免旧请求的响应覆盖新请求的响应。
 */
let cacheGeneration = 0

export function getEntitlements(force = false): Promise<EntitlementsResponse> {
  if (force) {
    // 强制刷新必须绕过 in-flight 去重：清掉缓存与在途引用，真正发起新请求；
    // 同时递增版本，让旧请求 resolve 后不能把过期数据写回缓存
    entitlementCache = null
    entitlementRequest = null
    cacheGeneration += 1
  }
  if (entitlementCache) return Promise.resolve(entitlementCache)
  if (!entitlementRequest) {
    // 在发起请求时锁定版本，回调里比对以识别期间是否发生过注销或强制刷新
    const generation = cacheGeneration
    const request = apiFetch<EntitlementsResponse>('/api/v1/auth/entitlements')
      .then((value) => {
        // 版本不匹配说明缓存已被清理：数据照常返回给当次调用者，但不写入缓存
        if (generation === cacheGeneration) entitlementCache = value
        return value
      })
      .finally(() => {
        // 只清理自己的引用：force/注销后可能有更新的请求在途，旧请求收尾时不能把新请求的引用一并清掉
        if (entitlementRequest === request) entitlementRequest = null
      })
    entitlementRequest = request
  }
  return entitlementRequest
}

export function clearApiCache(): void {
  cacheGeneration += 1
  entitlementCache = null
  entitlementRequest = null
}
