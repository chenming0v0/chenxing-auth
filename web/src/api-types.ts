export type ApiRequestInit = RequestInit & {
  redirectOn401?: boolean
  csrf?: 'required' | 'pre-session'
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

export type AuthStatusResponse = { authenticated: boolean }
export type LoginResponse = { expires_at?: string }
export type PendingLoginResponse = {
  status: 'factor_setup_required' | 'factor_required'
  methods: Array<'totp' | 'passkey' | string>
}
export type TotpSetupResponse = { secret_base32: string; otpauth_url: string }
export type SecurityFactorSummary = {
  totp_enabled: boolean
  passkey_count: number
  available_methods: Array<'totp' | 'passkey' | string>
}
export type SecurityTotpStart = TotpSetupResponse & { enrollment_id: string }
export type SecurityPasskeyStart = {
  enrollment_id: string
  options: { publicKey?: Record<string, unknown> }
}
export type SecurityEnrollmentResult = { method: 'totp' | 'passkey'; enabled: boolean }
export type SecurityRemovalResult = {
  method: 'totp' | 'passkey'
  removed: number
  credentials_revoked: boolean
}

export type ExternalIdentity = {
  provider: string
  provider_name: string
  /** Internal IdP subject is intentionally not exposed by the public API. */
  email: string
  linked_at: string
}
export type ExternalIdentityListResponse = { items: ExternalIdentity[] }
export type ExternalIdentityUnlinkInput = { password: string }

/** 登录页可见的外部身份源，仅包含渲染入口所需的公开字段。 */
export type PublicExternalProvider = { slug: string; name: string }

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

export type EntitlementPlan = {
  code: string
  name: string
  description?: string | null
  validity: string
}

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

export type OwnedOAuthClientList = { items: OwnedOAuthClient[]; total?: number }
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
export type IssuerRecordResponse = {
  value: string
  generation: number
  updated_at: string
}
export type IssuerSettingResponse = {
  persisted: IssuerRecordResponse | null
  loaded: IssuerRecordResponse | null
  phase: 'awaiting_issuer' | 'issuer_loaded' | 'issuer_invalid'
}
export type UpdateIssuerSetting = {
  value: string
  expected_generation: number
  confirm: boolean
}
export type AdminOverview = {
  users: number
  oauth_clients: number
  administrators: number
  audit_events: number
}
export type PublicUser = Omit<
  UserMe,
  'current_session_expires_at' | 'avatar_updated_at'
> & {
  created_at: string
  plan: {
    id: number
    code: string
    name: string
    expires_at: string | null
  } | null
}
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
/** 管理端公开注册设置（GET/PUT /api/v1/admin/settings/registration）。 */
export type RegistrationSetting = {
  enabled: boolean
  email_verification_required: boolean
  invitation_code_required: boolean
}
/**
 * 登录页可见的公开注册状态（GET /api/v1/auth/registration-status，匿名可读）。
 * 与管理端设置同形状，但 `enabled` 已是服务端计入 Issuer 闸门后的有效值。
 */
export type RegistrationStatus = {
  enabled: boolean
  email_verification_required: boolean
  invitation_code_required: boolean
}
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
  generation: number
}
export type UpdateEmailPolicySetting = Omit<EmailPolicySetting, 'generation'> & {
  expected_generation: number
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
export type SmtpPasswordAction = 'keep' | 'set' | 'clear'
export type SmtpSettingUpdate = {
  host: string
  port: number
  username: string
  from_address: string
  ssl_enabled: boolean
  force_auth_login: boolean
  password_action?: SmtpPasswordAction
  password?: string | null
}
export type SessionLifetimeSetting = {
  session_ttl_seconds: number
  session_idle_timeout_seconds: number
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
export type AuthorizationDecisionResponse = {
  decision: 'approve' | 'deny'
  redirect_to: string
}
