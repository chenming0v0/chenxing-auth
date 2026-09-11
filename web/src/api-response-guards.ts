import type {
  AccountProvider,
  AccountProviderListResponse,
  AdminMeResponse,
  AuthStatusResponse,
  AuthorizationDecisionResponse,
  ExternalIdentity,
  ExternalIdentityExtension,
  ExternalIdentityExtensionField,
  ExternalIdentityListResponse,
  LinkedAccount,
  LinkedAccountListResponse,
  PendingAuthorization,
  UserMe,
  UserRole,
} from './api-types'
import { isManagedAccountProvider } from './account-provider-types'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

const MAX_EXTERNAL_IDENTITY_ITEMS = 100
const MAX_EXTERNAL_IDENTITY_TEXT = 2048
const MAX_EXTERNAL_IDENTITY_EXTENSIONS = 32
const MAX_EXTERNAL_IDENTITY_FIELDS = 100

function isBoundedString(value: unknown, max = MAX_EXTERNAL_IDENTITY_TEXT): value is string {
  return typeof value === 'string' && value.length <= max
}

function isJsonValue(value: unknown, depth = 0): boolean {
  if (value === null || typeof value === 'boolean') return true
  if (typeof value === 'string') return value.length <= 4096
  if (typeof value === 'number') return Number.isFinite(value)
  if (depth > 5 || typeof value !== 'object') return false
  if (Array.isArray(value)) return value.length <= MAX_EXTERNAL_IDENTITY_FIELDS && value.every((item) => isJsonValue(item, depth + 1))
  return Object.entries(value).length <= MAX_EXTERNAL_IDENTITY_FIELDS
    && Object.entries(value).every(([key, item]) => isBoundedString(key, 128) && isJsonValue(item, depth + 1))
}

function isExternalIdentityExtensionField(value: unknown): value is ExternalIdentityExtensionField {
  if (!isRecord(value)
    || !isBoundedString(value.key, 128)
    || !isBoundedString(value.label, 256)
    || !isBoundedString(value.type, 64)
    || !isJsonValue(value.value)) return false
  if (value.type === 'number' || value.type === 'duration_days') return typeof value.value === 'number' && Number.isFinite(value.value)
  if (value.type === 'boolean') return typeof value.value === 'boolean'
  if (value.type === 'text' || value.type === 'status' || value.type === 'datetime' || value.type === 'url') return isBoundedString(value.value, 4096)
  // Unknown field types are retained so the UI can render a safe unsupported marker.
  return true
}

function isExternalIdentityExtension(value: unknown): value is ExternalIdentityExtension {
  return isRecord(value)
    && isBoundedString(value.namespace, 128)
    && (isBoundedString(value.version, 64) || (typeof value.version === 'number' && Number.isSafeInteger(value.version) && value.version >= 0))
    && isBoundedString(value.fetched_at, 128)
    && Array.isArray(value.fields)
    && value.fields.length <= MAX_EXTERNAL_IDENTITY_FIELDS
    && value.fields.every(isExternalIdentityExtensionField)
}

function isExternalIdentity(value: unknown): value is ExternalIdentity {
  if (!isRecord(value)
    || !isBoundedString(value.provider, 128)
    || !isBoundedString(value.provider_name, 256)
    || !isBoundedString(value.email, 320)
    || !isBoundedString(value.linked_at, 128)) return false
  const optionalStrings = [
    ['account_name', 256],
    ['name', 256],
    ['avatar_url', 4096],
    ['provider_icon', 4096],
    ['subject_hint', 512],
    ['status', 64],
    ['last_synced_at', 128],
    ['sync_status', 64],
    ['sync_error', 512],
  ] as const
  for (const [key, max] of optionalStrings) {
    if (value[key] !== undefined && value[key] !== null && !isBoundedString(value[key], max)) return false
  }
  return (value.extensions === undefined
    || (Array.isArray(value.extensions)
      && value.extensions.length <= MAX_EXTERNAL_IDENTITY_EXTENSIONS
      && value.extensions.every(isExternalIdentityExtension)))
}

function isExternalIdentityListResponse(value: unknown): value is ExternalIdentityListResponse {
  return isRecord(value)
    && Array.isArray(value.items)
    && value.items.length <= MAX_EXTERNAL_IDENTITY_ITEMS
    && value.items.every(isExternalIdentity)
}

/** guard 上限与 openapi.yaml maxItems/maxLength 对齐；超出即整体拒绝，不做半截渲染。 */
const MAX_LINKED_ACCOUNT_ITEMS = 100

function isNullableBoundedString(value: unknown, max: number): boolean {
  return value === null || isBoundedString(value, max)
}

function isAccountProvider(value: unknown): value is AccountProvider {
  if (!isRecord(value)
    || !isBoundedString(value.id, 128)
    || !isBoundedString(value.name, 256)
    || !isNullableBoundedString(value.icon_url, 4096)
    || value.kind !== 'service_account'
    || value.binding_method !== 'credentials'
    || typeof value.can_refresh !== 'boolean') return false
  return Object.keys(value).every((key) =>
    ['id', 'name', 'icon_url', 'kind', 'binding_method', 'can_refresh'].includes(key))
}

function isAccountProviderListResponse(value: unknown): value is AccountProviderListResponse {
  return isRecord(value)
    && Array.isArray(value.items)
    && value.items.length <= MAX_LINKED_ACCOUNT_ITEMS
    && value.items.every(isAccountProvider)
}

function isLinkedAccount(value: unknown): value is LinkedAccount {
  if (!isRecord(value)
    || !isBoundedString(value.id, 128)
    || (value.kind !== 'service_account' && value.kind !== 'oauth_identity')
    || !isNullableBoundedString(value.uid, 255)
    || !isNullableBoundedString(value.subject_hint, 512)
    || !isBoundedString(value.account_status, 64)
    || !isBoundedString(value.linked_at, 128)) return false
  if (!isRecord(value.provider)
    || !isBoundedString(value.provider.id, 128)
    || !isBoundedString(value.provider.name, 256)
    || !isNullableBoundedString(value.provider.icon_url, 4096)) return false
  if (!isRecord(value.display)
    || !isNullableBoundedString(value.display.name, 512)
    || !isNullableBoundedString(value.display.email, 512)
    || !isNullableBoundedString(value.display.avatar_url, 4096)) return false
  if (!isRecord(value.capabilities)
    || typeof value.capabilities.can_login !== 'boolean'
    || typeof value.capabilities.can_refresh !== 'boolean') return false
  if (!isRecord(value.sync)
    || !isBoundedString(value.sync.status, 64)
    || !isNullableBoundedString(value.sync.last_attempt_at, 128)
    || !isNullableBoundedString(value.sync.last_success_at, 128)
    || !isNullableBoundedString(value.sync.stale_after, 128)
    || !isNullableBoundedString(value.sync.refresh_after, 128)
    || !isNullableBoundedString(value.sync.error, 512)) return false
  return Array.isArray(value.extensions)
    && value.extensions.length <= MAX_EXTERNAL_IDENTITY_EXTENSIONS
    && value.extensions.every(isExternalIdentityExtension)
}

function isLinkedAccountListResponse(value: unknown): value is LinkedAccountListResponse {
  return isRecord(value)
    && Array.isArray(value.items)
    && value.items.length <= MAX_LINKED_ACCOUNT_ITEMS
    && value.items.every(isLinkedAccount)
    && (value.next_cursor === null || isBoundedString(value.next_cursor, 512))
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
    /* 头像版本号缺失时容忍而不整体拒绝：它只影响头像是否渲染（缺失即回落到
       首字母），而拒掉整个 /auth/me 会让用户完全进不去控制台。承载语义的
       id / username / role / status 仍然严格必需。 */
    && (value.avatar_updated_at === null
      || value.avatar_updated_at === undefined
      || typeof value.avatar_updated_at === 'string')
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

export function responseGuard(path: string, method: string): ResponseGuard | undefined {
  const endpoint = path.split('?')[0]
  if (endpoint === '/api/v1/admin/account-providers' && method === 'GET') {
    return (value) => Array.isArray(value) && value.every(isManagedAccountProvider)
  }
  if (/^\/api\/v1\/admin\/account-providers\/[^/]+$/.test(endpoint) && method === 'PUT') return isManagedAccountProvider
  if (endpoint === '/api/v1/auth/me') return isUserMeResponse
  // 头像的 PUT / DELETE 返回完整资料；GET 返回图片字节，不走 apiFetch。
  if (endpoint === '/api/v1/auth/me/avatar' && (method === 'PUT' || method === 'DELETE')) {
    return isUserMeResponse
  }
  if (endpoint === '/api/v1/auth/status') return isAuthStatusResponse
  if (endpoint === '/api/v1/admin/auth/me') return isAdminMeResponse
  if (endpoint === '/api/v1/auth/external-identities' && method === 'GET') return isExternalIdentityListResponse
  if (endpoint === '/api/v1/auth/linked-accounts' && method === 'GET') return isLinkedAccountListResponse
  if (endpoint === '/api/v1/auth/account-providers' && method === 'GET') return isAccountProviderListResponse

  const linkedAccountEndpoint = /^\/api\/v1\/auth\/linked-accounts\/[^/]+$/
  if (linkedAccountEndpoint.test(endpoint) && method === 'GET') return isLinkedAccount
  const linkedAccountWriteEndpoint = /^\/api\/v1\/auth\/linked-accounts\/[^/]+\/(refresh)$/
  if (linkedAccountWriteEndpoint.test(endpoint) && method === 'POST') return isLinkedAccount
  const linkedAccountBindEndpoint = /^\/api\/v1\/auth\/account-providers\/[^/]+\/bindings$/
  if (linkedAccountBindEndpoint.test(endpoint) && method === 'POST') return isLinkedAccount

  const pendingEndpoint = /^\/api\/v1\/oauth\/authorize\/requests\/[^/]+$/
  if (pendingEndpoint.test(endpoint)) {
    if (method === 'GET') return isPendingAuthorizationResponse
    if (method === 'POST') return isAuthorizationDecisionResponse
  }
  return undefined
}
