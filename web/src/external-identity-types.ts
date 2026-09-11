export type ExternalIdentityExtensionFieldType =
  | 'text'
  | 'number'
  | 'boolean'
  | 'status'
  | 'datetime'
  | 'duration_days'
  | 'url'
  | (string & {})

export type ExternalIdentityExtensionField = {
  key: string
  label: string
  type: ExternalIdentityExtensionFieldType
  value: unknown
}

export type ExternalIdentityExtension = {
  namespace: string
  version: string | number
  fields: ExternalIdentityExtensionField[]
  fetched_at: string
}

export type ExternalIdentity = {
  provider: string
  provider_name: string
  /** Internal IdP subject is intentionally not exposed by the public API. */
  email: string
  linked_at: string
  /** Optional account snapshot fields supplied by provider adapters. */
  account_name?: string | null
  name?: string | null
  avatar_url?: string | null
  provider_icon?: string | null
  /** A server-redacted subject summary; never a raw provider subject. */
  subject_hint?: string | null
  status?: string
  last_synced_at?: string | null
  sync_status?: 'success' | 'failed' | 'pending' | string
  sync_error?: string | null
  extensions?: ExternalIdentityExtension[]
}

export type ExternalIdentityListResponse = { items: ExternalIdentity[] }

/* ====== 已连接账号（Issue #706）：/api/v1/auth/linked-accounts 聚合契约 ======
   LinkedAccount 统一承载 OAuth 外部身份（kind: oauth_identity）与业务服务账号
   （kind: service_account，当前只有 CLtermux）。字段与 openapi.yaml 一一对应。 */

export type LinkedAccountKind = 'service_account' | 'oauth_identity'

/** 可绑定的业务账号供应商描述（GET /api/v1/auth/account-providers）。 */
export type AccountProvider = {
  id: string
  name: string
  icon_url: string | null
  kind: 'service_account'
  binding_method: 'credentials'
  can_refresh: boolean
}

export type AccountProviderListResponse = { items: AccountProvider[] }

export type LinkedAccountProvider = {
  id: string
  name: string
  icon_url: string | null
}

export type LinkedAccountDisplay = {
  name: string | null
  email: string | null
  avatar_url: string | null
}

export type LinkedAccountCapabilities = {
  can_login: boolean
  can_refresh: boolean
}

export type LinkedAccountSync = {
  status: 'never' | 'success' | 'failed' | 'unsupported' | string
  last_attempt_at: string | null
  last_success_at: string | null
  stale_after: string | null
  refresh_after: string | null
  error: string | null
}

export type LinkedAccount = {
  id: string
  kind: LinkedAccountKind
  provider: LinkedAccountProvider
  uid: string | null
  /** 服务端已脱敏的 subject 摘要；永不返回原始 provider subject。 */
  subject_hint: string | null
  display: LinkedAccountDisplay
  account_status: 'active' | 'disabled' | 'missing' | 'unknown' | string
  linked_at: string
  capabilities: LinkedAccountCapabilities
  sync: LinkedAccountSync
  extensions: ExternalIdentityExtension[]
}

/**
 * 游标分页：无更多结果时 next_cursor 为 null。
 * cursor 是服务端生成的不透明值，客户端只允许原样回传，不得解码或修改。
 */
export type LinkedAccountListResponse = {
  items: LinkedAccount[]
  next_cursor: string | null
}

/** 业务服务账号凭据绑定入参（POST /api/v1/auth/account-providers/{provider}/bindings）。 */
export type LinkedAccountCredentialBindInput = { public_key: string; private_key: string }
/** 解绑入参（DELETE /api/v1/auth/linked-accounts/{id}），密码只做当次复验，永不缓存。 */
export type LinkedAccountDeleteInput = { password: string }
