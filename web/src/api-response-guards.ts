import type {
  AdminMeResponse,
  AuthStatusResponse,
  AuthorizationDecisionResponse,
  PendingAuthorization,
  UserMe,
  UserRole,
} from './api'

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
  if (endpoint === '/api/v1/auth/me') return isUserMeResponse
  // 头像的 PUT / DELETE 返回完整资料；GET 返回图片字节，不走 apiFetch。
  if (endpoint === '/api/v1/auth/me/avatar' && (method === 'PUT' || method === 'DELETE')) {
    return isUserMeResponse
  }
  if (endpoint === '/api/v1/auth/status') return isAuthStatusResponse
  if (endpoint === '/api/v1/admin/auth/me') return isAdminMeResponse

  const pendingEndpoint = /^\/api\/v1\/oauth\/authorize\/requests\/[^/]+$/
  if (pendingEndpoint.test(endpoint)) {
    if (method === 'GET') return isPendingAuthorizationResponse
    if (method === 'POST') return isAuthorizationDecisionResponse
  }
  return undefined
}
