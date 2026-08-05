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

function csrfToken(): string | undefined {
  if (typeof document === 'undefined') return undefined
  const value = document.cookie
    .split(';')
    .map((cookie) => cookie.trim())
    .find((cookie) => cookie.startsWith('chenxing_csrf='))
    ?.slice('chenxing_csrf='.length)
  if (!value) return undefined
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

const safeMessages: Record<string, string> = {
  invalid_credentials: '账号或密码不正确。',
  invalid_factor: '验证码不正确，请重试。',
  invalid_login_ticket: '验证流程已失效，请重新登录。',
  email_already_registered: '注册信息无法使用，请检查后重试。',
  email_domain_not_allowed: '当前邮箱域名不允许注册。',
  passkey_disabled: 'Passkey 登录尚未启用。',
  username_already_registered: '注册信息无法使用，请检查后重试。',
  oauth_client_quota_exceeded: '当前套餐的 OAuth 应用额度已用尽。',
  oauth_quota_exceeded: '当前 OAuth 授权额度已用尽。',
  authorization_request_expired: '授权请求已过期，请重新发起。',
  authorization_request_processed: '授权请求已经处理过。',
  csrf_invalid: '请求校验失败，请刷新页面后重试。',
  csrf_required: '请求校验失败，请刷新页面后重试。',
  invalid_plan: '套餐参数不正确，请检查输入。',
  plan_not_found: '套餐不存在或已失效。',
  plan_code_conflict: '套餐代码已被占用，请更换。',
  default_plan_protected: '默认套餐不能取消默认标记或归档。',
  archived_plan_default: '已归档的套餐不能设为默认。',
  plan_archived: '已归档的套餐不能分配给用户。',
  invalid_expiration: '到期时间格式不正确，请重新选择。',
  oauth_provider_not_found: '该外部身份源不可用或已被停用。',
  oauth_login_failed: '外部身份源登录未完成，请重试。',
  oauth_login_rate_limited: '外部登录尝试过于频繁，请稍后重试。',
  oauth_request_expired: '授权请求已过期，请重新发起。',
  oauth_request_binding_failed: '授权请求绑定失败，请重新开始。',
  oauth_account_link_required: '该外部账号尚未绑定辰星通行证，请先登录后在账号设置中绑定。',
}

function safeErrorMessage(status: number, code?: string): string {
  if (code && safeMessages[code]) return safeMessages[code]
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

export async function apiFetch<T>(path: string, init: ApiRequestInit = {}): Promise<T> {
  const { redirectOn401 = true, ...requestInit } = init
  const method = requestInit.method?.toUpperCase() ?? 'GET'
  const headers = new Headers(requestInit.headers)
  headers.set('Accept', 'application/json')
  if (method !== 'GET' && method !== 'HEAD') {
    if (!(requestInit.body instanceof FormData)) headers.set('Content-Type', 'application/json')
    const token = csrfToken()
    if (token) headers.set('X-CSRF-Token', token)
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
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
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
  login_ticket: string
  methods: Array<'totp' | 'passkey' | string>
}
export type TotpSetupResponse = { secret_base32: string; otpauth_url: string }

/** 登录页可见的外部身份源，仅包含渲染入口所需的公开字段。 */
export type PublicExternalProvider = { slug: string; name: string }

/** 外部登录失败时后端回跳 /login?external_error=<code>，此处复用统一文案表。 */
export function externalLoginErrorMessage(code: string): string {
  return safeMessages[code] ?? '外部身份源登录未完成，请重试。'
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

export type EntitlementsResponse = {
  plan: { code: string; name: string; description?: string | null; validity: string }
  entitlements: EntitlementItem[]
}

export type QuotaSnapshot = {
  daily_limit: number
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

export function getEntitlements(force = false): Promise<EntitlementsResponse> {
  if (force) entitlementCache = null
  if (entitlementCache) return Promise.resolve(entitlementCache)
  if (!entitlementRequest) {
    entitlementRequest = apiFetch<EntitlementsResponse>('/api/v1/auth/entitlements')
      .then((value) => { entitlementCache = value; return value })
      .finally(() => { entitlementRequest = null })
  }
  return entitlementRequest
}

export function clearApiCache(): void {
  entitlementCache = null
  entitlementRequest = null
}
