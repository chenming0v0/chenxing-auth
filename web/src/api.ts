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

export type ApiRequestInit = RequestInit & { redirectOn401?: boolean }

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
  ['oauth_login_failed', '外部身份源登录未完成，请重试。'],
  ['oauth_login_rate_limited', '外部登录尝试过于频繁，请稍后重试。'],
  ['oauth_request_expired', '授权请求已过期，请重新发起。'],
  ['oauth_request_binding_failed', '授权请求绑定失败，请重新开始。'],
  ['oauth_account_link_required', '该外部账号尚未绑定辰星通行证，请先登录后在账号设置中绑定。'],
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

function redirectToLogin(): void {
  if (typeof window === 'undefined' || window.location.pathname === '/login') return
  const returnTo = `${window.location.pathname}${window.location.search}`
  const target = `/login?returnTo=${encodeURIComponent(returnTo)}`
  window.history.replaceState({}, '', target)
  window.dispatchEvent(new PopStateEvent('popstate'))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isUserRole(value: unknown): value is UserRole {
  return value === 'user' || value === 'admin' || value === 'owner'
}

function isUserMeResponse(value: unknown): value is UserMe {
  return isRecord(value)
    && typeof value.id === 'number'
    && Number.isFinite(value.id)
    && typeof value.username === 'string'
    && typeof value.email === 'string'
    && (value.display_name === null || typeof value.display_name === 'string')
    && typeof value.status === 'string'
    && isUserRole(value.role)
    && typeof value.current_session_expires_at === 'string'
}

function isAuthStatusResponse(value: unknown): value is AuthStatusResponse {
  return isRecord(value) && typeof value.authenticated === 'boolean'
}

function isAdminMeResponse(value: unknown): value is AdminMeResponse {
  if (!isRecord(value)) return false
  const userIdValid = value.user_id === undefined
    || value.user_id === null
    || (typeof value.user_id === 'number' && Number.isFinite(value.user_id))
  const usernameValid = value.username === undefined
    || value.username === null
    || typeof value.username === 'string'
  return userIdValid
    && usernameValid
    && (value.role === 'admin' || value.role === 'owner')
    && isStringArray(value.permissions)
    && typeof value.status === 'string'
}

function isPendingAuthorizationResponse(value: unknown): value is PendingAuthorization {
  return isRecord(value)
    && typeof value.request_id === 'string'
    && typeof value.client_id === 'string'
    && typeof value.client_name === 'string'
    && typeof value.redirect_host === 'string'
    && isStringArray(value.scopes)
    && typeof value.expires_in === 'number'
    && Number.isFinite(value.expires_in)
}

function isAuthorizationDecisionResponse(value: unknown): value is AuthorizationDecisionResponse {
  return isRecord(value)
    && (value.decision === 'approve' || value.decision === 'deny')
    && typeof value.redirect_to === 'string'
}

type ResponseGuard = (value: unknown) => boolean

function responseGuard(path: string, method: string): ResponseGuard | undefined {
  const endpoint = path.split('?')[0]
  if (endpoint === '/api/v1/auth/me') return isUserMeResponse
  if (endpoint === '/api/v1/auth/status') return isAuthStatusResponse
  if (endpoint === '/api/v1/admin/auth/me') return isAdminMeResponse

  const pendingEndpoint = /^\/api\/v1\/oauth\/authorize\/requests\/[^/]+$/
  if (pendingEndpoint.test(endpoint)) {
    if (method === 'GET') return isPendingAuthorizationResponse
    if (method === 'POST') return isAuthorizationDecisionResponse
  }
  return undefined
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
  const { redirectOn401 = true, ...requestInit } = init
  const method = normalizeMethod(requestInit.method)
  const headers = new Headers(requestInit.headers)
  headers.set('Accept', 'application/json')
  if (!SAFE_HTTP_METHODS.has(method)) {
    if (!(requestInit.body instanceof FormData)) headers.set('Content-Type', 'application/json')
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', token)
    else if (!headers.has('X-CSRF-Token')) throw missingCsrfError()
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
export type PublicUser = Omit<UserMe, 'current_session_expires_at'> & { created_at: string }
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
  email_verified_claim?: string | null
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
