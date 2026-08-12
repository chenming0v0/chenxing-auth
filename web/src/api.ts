import { responseGuard } from './api-response-guards'

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

export type ApiRequestInit = RequestInit & {
  redirectOn401?: boolean
  csrf?: 'required' | 'pre-session'
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
])

/** 安全错误码文案映射，使用 Map 避免原型链污染（Object 字面量索引可访问 constructor 等原型属性）。 */
const safeMessages = new Map<string, string>([
  ['invalid_credentials', '账号或密码不正确。'],
  ['invalid_factor', '验证码不正确，请重试。'],
  ['invalid_login_ticket', '验证流程已失效，请重新登录。'],
  ['email_already_registered', '注册信息无法使用，请检查后重试。'],
  ['email_domain_not_allowed', '当前邮箱域名不允许注册。'],
  ['passkey_disabled', 'Passkey 登录尚未启用。'],
  ['username_already_registered', '注册信息无法使用，请检查后重试。'],
  ['invalid_username', '用户名格式不正确，请检查长度和字符。'],
  ['invalid_email', '邮箱格式不正确，请检查输入。'],
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
  window.history.replaceState({}, '', target)
  window.dispatchEvent(new PopStateEvent('popstate'))
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

export type UserRole = 'user' | 'admin' | 'owner'

export type UserMe = {
  id: number
  username: string
  email: string
  display_name: string | null
  status: string
  role: UserRole
  current_session_expires_at: string
  /** 头像版本时间戳；null 表示未设置头像，界面回落到首字母占位符。 */
  avatar_updated_at: string | null
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

export type AuthStatusResponse = { authenticated: boolean }
export type LoginResponse = { expires_at?: string }
export type PendingLoginResponse = {
  status: 'factor_setup_required' | 'factor_required'
  methods: Array<'totp' | 'passkey' | string>
}
export type TotpSetupResponse = { secret_base32: string; otpauth_url: string }

/** 登录页可见的外部身份源，仅包含渲染入口所需的公开字段。 */
export type PublicExternalProvider = { slug: string; name: string }

/**
 * 外部登录失败时后端回跳 /login?external_error=<code>，此处复用统一文案表。
 * code 直接来自 URL 查询参数，必须经 Map 查表，避免命中 Object.prototype 上的
 * constructor / toString 等成员导致 React 渲染函数子节点而整页崩溃。
 */
export function externalLoginErrorMessage(code: string): string {
  return safeMessages.get(code) ?? '外部身份源登录未完成，请重试。'
}

export type SessionItem = {
  id: number
  created_at: string
  expires_at: string
  current: boolean
}

export type EntitlementItem = {
  key: string
  label: string
  used: number
  limit?: number | null
  remaining?: number | null
}

export type EntitlementPlan = { code: string; name: string; description?: string | null; validity: string }

/**
 * plan 为 null 是合法状态，语义是「平台未开放自助接入」（系统里没有可回退的默认套餐）。
 * 此时 entitlements 为空数组，前端以 plan === null 作为该状态的唯一判据，不另设状态字段。
 */
export type EntitlementsResponse = {
  plan: EntitlementPlan | null
  entitlements: EntitlementItem[]
}

export type QuotaSnapshot = {
  /** null 表示没有每日上限概念（无套餐时服务端不给出数值） */
  daily_limit: number | null
  daily_used: number
  monthly_limit: number | null
  monthly_used: number
}

export type OwnedOAuthClient = {
  id: number
  client_id: string
  client_name: string
  redirect_uris: string[]
  scopes: string[]
  status: string
  quota: QuotaSnapshot
}

export type OwnedOAuthClientList = { items: OwnedOAuthClient[] }
export type RegisteredOwnedOAuthClient = OwnedOAuthClient & { client_secret: string }
export type ClientSecretResponse = { client_id: string; client_secret: string }
export type ClientInput = { client_name: string; redirect_uris: string[]; scopes: string[] }
export type AuthorizedOAuthApp = {
  client_id: string
  client_name: string
  scopes: string[]
  updated_at: string
}
export type AuthorizedOAuthAppList = { items: AuthorizedOAuthApp[] }

export type AdminMeResponse = {
  user_id?: number | null
  username?: string | null
  role: 'admin' | 'owner'
  permissions: string[]
  status: string
}
export type AdminOverview = { users: number; oauth_clients: number; administrators: number; audit_events: number }
/** 管理端用户对象。该接口不返回头像版本号，因此显式排除，避免类型宣称后端没给的字段。 */
export type PublicUser = Omit<UserMe, 'current_session_expires_at' | 'avatar_updated_at'> & { created_at: string }
/** 管理端建号入参；display_name 留空时传 null，role / status 省略时由服务端取默认值。 */
export type AdminCreateUserInput = {
  username: string
  email: string
  password: string
  display_name: string | null
  role: UserRole
  status: 'active' | 'disabled'
}
export type Paged<T> = { items: T[]; page: number; page_size: number; total: number }
export type ClientSummary = ClientInput & {
  id?: number
  client_id: string
  status: string
  owner_user_id?: number | null
}
export type AuditEvent = {
  id?: number
  actor_type?: string
  actor_id?: string | null
  action?: string
  resource_type?: string
  resource_id?: string | null
  created_at?: string
}
/** 用户级安全日志事件（GET /api/v1/auth/security-events，后端实现见 issue #307）。 */
export type SecurityEvent = {
  id: number
  action: string
  resource_type: string | null
  client_id: string | null
  client_name: string | null
  created_at: string
}
/** 安全日志详情（GET /api/v1/auth/security-events/{id}，契约提案见 issue #308）。
    敏感字段（ip/user_agent 等）后端未记录时为 null，前端默认打码展示。 */
export type SecurityEventClient = {
  client_id: string
  client_name: string
  created_at: string | null
  status: string | null
}
export type SecurityEventDetail = SecurityEvent & {
  category: string | null
  severity: string | null
  ip: string | null
  ip_location: string | null
  user_agent: string | null
  ray_id: string | null
  client: SecurityEventClient | null
}
export type RegistrationEmailSetting = { registration_email_from: string | null }
export type PasskeyUserVerification = 'preferred' | 'required' | 'discouraged'
export type PasskeyAuthenticatorAttachment = 'any' | 'platform' | 'cross_platform'
export type PasskeySetting = {
  enabled: boolean
  rp_name: string
  rp_id: string
  user_verification: PasskeyUserVerification
  authenticator_attachment: PasskeyAuthenticatorAttachment
  allow_insecure_origin: boolean
  allowed_origins: string[]
}
export type EmailPolicySetting = {
  whitelist_enabled: boolean
  alias_restriction_enabled: boolean
  allowed_domains: string[]
}
export type SmtpSetting = {
  host: string
  port: number
  username: string
  from_address: string
  ssl_enabled: boolean
  force_auth_login: boolean
  password_configured: boolean
}
export type SmtpSettingUpdate = {
  host: string
  port: number
  username: string
  from_address: string
  ssl_enabled: boolean
  force_auth_login: boolean
  password?: string | null
}
export type SecurityLimitsSetting = {
  unauthenticated_source_qps: number
  authorization_code_ttl_seconds: number
  pending_request_ttl_seconds: number
  max_pending_requests_per_client: number
  max_pending_requests_global: number
  auth_failure_window_seconds: number
  account_failure_limit: number
  ip_failure_limit: number
  totp_ticket_failure_limit: number
  external_login_state_ttl_seconds: number
  external_login_state_rate_window_seconds: number
  external_login_state_rate_limit: number
  external_login_state_max_pending: number
}
export type OAuthProviderSummary = {
  id: number
  name: string
  slug: string
  /**
   * 身份信任模型（Issue #296）。恒为 `oauth2_userinfo`：OAuth 2.0 授权码流程 + UserInfo 端点，
   * `sub`/`email`/`email_verified` 全部来自 UserInfo 响应，令牌响应中的 `id_token` 不被解析，
   * 本平台在这一侧不是 OIDC 依赖方。新增模式时后端会新增取值，而不是放宽这个取值的含义。
   */
  trust_model?: 'oauth2_userinfo' | string
  callback_uri?: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  client_id: string
  scopes: string[]
  subject_claim: string
  email_claim: string
  name_claim?: string | null
  email_verified_claim?: string | null
  client_auth_method: 'basic' | 'request_body'
  status: 'active' | 'disabled' | string
  client_secret_configured: boolean
}
export type OAuthProviderInput = {
  name: string
  slug: string
  authorization_endpoint: string
  token_endpoint: string
  userinfo_endpoint: string
  client_id: string
  client_secret?: string | null
  scopes: string[]
  subject_claim?: string
  email_claim?: string
  name_claim?: string | null
  /** 必填：指向布尔型邮箱验证状态的 claim 路径。缺失时后端拒绝配置（Issue #261）。 */
  email_verified_claim: string
  client_auth_method?: 'basic' | 'request_body'
}
export type AdminPlan = {
  id: number
  code: string
  name: string
  description: string | null
  oauth_clients_limit: number
  daily_auth_limit: number
  /** null 表示无限额度 */
  monthly_auth_limit: number | null
  /** null 表示不限并发 */
  max_qps: number | null
  is_default: boolean
  status: 'active' | 'archived' | string
  assigned_users: number
}
export type AdminPlanInput = {
  code: string
  name: string
  description: string | null
  oauth_clients_limit: number
  daily_auth_limit: number
  monthly_auth_limit: number | null
  max_qps: number | null
  is_default: boolean
}
export type AssignPlanInput = { plan_id: number; expires_at: string | null }
export type KeyRotationResponse = { key_id: string; published_key_count: number }
export type PendingAuthorization = {
  request_id: string
  client_id: string
  client_name: string
  redirect_host: string
  scopes: string[]
  expires_in: number
}
export type AuthorizationDecisionResponse = { decision: 'approve' | 'deny'; redirect_to: string }

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
 * 缓存版本计数器。clearApiCache()（注销时调用）递增它，使注销前发出的 in-flight 请求
 * 在 resolve 后无法把上一个用户的权益数据写回缓存，避免跨用户泄露。
 */
let cacheGeneration = 0

export function getEntitlements(force = false): Promise<EntitlementsResponse> {
  if (force) entitlementCache = null
  if (entitlementCache) return Promise.resolve(entitlementCache)
  if (!entitlementRequest) {
    // 在发起请求时锁定版本，回调里比对以识别期间是否发生过注销
    const generation = cacheGeneration
    entitlementRequest = apiFetch<EntitlementsResponse>('/api/v1/auth/entitlements')
      .then((value) => {
        // 版本不匹配说明缓存已被清理：数据照常返回给当次调用者，但不写入缓存
        if (generation === cacheGeneration) entitlementCache = value
        return value
      })
      .finally(() => {
        // 无条件清理 in-flight 引用，避免注销后的新请求复用上一个会话的 Promise
        entitlementRequest = null
      })
  }
  return entitlementRequest
}

export function clearApiCache(): void {
  cacheGeneration += 1
  entitlementCache = null
  entitlementRequest = null
}
