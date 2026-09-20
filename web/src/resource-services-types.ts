/** 资源服务开放范围：restricted = 仅 allowed_client_ids 中的应用可申请该 scope；public = 本站所有应用可申请。 */
export type ResourceServiceScopeAccess = 'restricted' | 'public'

export type ResourceServicePublicProvider = {
  id: string
  slug: string
  display_name: string
  issuer: string
  identifier_label: string
  secret_label: string
  identifier_sensitive: boolean
}

export type ResourceServiceAdminProvider = ResourceServicePublicProvider & {
  client_id: string
  scope: string
  scope_description: string
  scope_access: ResourceServiceScopeAccess
  allowed_client_ids: string[]
  enabled: boolean
  revision: number
  identity_locked: boolean
}

export type ResourceServiceBinding = {
  id: string
  provider_id: string
  issuer: string
  uid: string
  account: string | null
  name: string | null
  status: string | null
  snapshot: Record<string, unknown>
  grant_expires_at: string | null
  access_expires_at: string | null
  refresh_expires_at: string | null
}

/** Account Provider v1 的订阅描述（protocol.md §9）。 */
export type ResourceServiceSubscription =
  | { kind: 'expires_at'; expires_at: string }
  | { kind: 'remaining'; remaining_seconds: number; as_of: string }
  | { kind: 'permanent' }
  | { kind: 'none' }
  | { kind: 'unknown' }

export type ResourceServiceAccountStatus = 'active' | 'disabled' | 'unknown'

/** 提供方自述的展示字段，按 `type` 区分取值类型；未知类型在解析阶段丢弃。 */
export type ResourceServiceSnapshotField = { key: string; label: string } & (
  | { type: 'text'; value: string }
  | { type: 'number'; value: number }
  | { type: 'boolean'; value: boolean }
  | { type: 'status'; value: string }
  | { type: 'datetime'; value: string }
  | { type: 'duration'; value: number }
  | { type: 'url'; value: string }
)

/**
 * 页面使用的快照视图。服务端已经校验过协议，这里只做宽松归一化：
 * 缺失的顶层键退化为 null / 空数组，绝不因为快照不完整而拒绝渲染绑定。
 */
export type ResourceServiceSnapshot = {
  uid: string | null
  account: string | null
  name: string | null
  status: ResourceServiceAccountStatus
  subscription: ResourceServiceSubscription | null
  fields: ResourceServiceSnapshotField[]
  fetched_at: string | null
}

export type ResourceServiceProviderInput = {
  display_name: string
  slug: string
  issuer: string
  client_id: string
  client_secret?: string
  /** 省略时服务端取 `<slug>:access`。 */
  scope?: string
  scope_description: string
  scope_access: ResourceServiceScopeAccess
  allowed_client_ids: string[]
  expected_revision: number
}

export type ResourceServiceBindingCreateInput = {
  provider_id: string
  identifier: string
  secret: string
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isOptionalString(value: unknown): value is string | null {
  return value === null || typeof value === 'string'
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

export function isResourceServiceScopeAccess(value: unknown): value is ResourceServiceScopeAccess {
  return value === 'restricted' || value === 'public'
}

const SECRET_FIELDS = ['client_secret', 'token', 'access_token', 'refresh_token', 'token_bundle_ciphertext']

function hasNoSecrets(value: Record<string, unknown>): boolean {
  return SECRET_FIELDS.every((field) => !(field in value))
}

export function isResourceServicePublicProvider(value: unknown): value is ResourceServicePublicProvider {
  if (!isRecord(value) || !hasNoSecrets(value)) return false
  return typeof value.id === 'string'
    && typeof value.slug === 'string'
    && typeof value.display_name === 'string'
    && typeof value.issuer === 'string'
    && typeof value.identifier_label === 'string'
    && typeof value.secret_label === 'string'
    && typeof value.identifier_sensitive === 'boolean'
}

export function isResourceServiceAdminProvider(value: unknown): value is ResourceServiceAdminProvider {
  if (!isResourceServicePublicProvider(value) || !isRecord(value)) return false
  const item = value as Record<string, unknown>
  return typeof item.client_id === 'string'
    && typeof item.scope === 'string'
    && typeof item.scope_description === 'string'
    && isResourceServiceScopeAccess(item.scope_access)
    && isStringArray(item.allowed_client_ids)
    && typeof item.enabled === 'boolean'
    && Number.isSafeInteger(item.revision)
    && Number(item.revision) >= 1
    && typeof item.identity_locked === 'boolean'
}

export function isResourceServiceBinding(value: unknown): value is ResourceServiceBinding {
  if (!isRecord(value) || !hasNoSecrets(value) || !isRecord(value.snapshot)) return false
  return typeof value.id === 'string'
    && typeof value.provider_id === 'string'
    && typeof value.issuer === 'string'
    && typeof value.uid === 'string'
    && isOptionalString(value.account)
    && isOptionalString(value.name)
    && isOptionalString(value.status)
    && isOptionalString(value.grant_expires_at)
    && isOptionalString(value.access_expires_at)
    && isOptionalString(value.refresh_expires_at)
}

export function isResourceServiceAdminProviderList(value: unknown): value is ResourceServiceAdminProvider[] {
  return Array.isArray(value) && value.every(isResourceServiceAdminProvider)
}

export function isResourceServicePublicProviderList(value: unknown): value is ResourceServicePublicProvider[] {
  return Array.isArray(value) && value.every(isResourceServicePublicProvider)
}

export function isResourceServiceBindingList(value: unknown): value is ResourceServiceBinding[] {
  return Array.isArray(value) && value.every(isResourceServiceBinding)
}

function optionalString(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function isHttpsUrl(value: unknown): value is string {
  if (typeof value !== 'string') return false
  try {
    return new URL(value).protocol === 'https:'
  } catch {
    return false
  }
}

function parseAccountStatus(value: unknown): ResourceServiceAccountStatus {
  return value === 'active' || value === 'disabled' ? value : 'unknown'
}

/** 认得的 kind 但取值残缺，与完全陌生的 kind 一样按 unknown 处理，页面只需应对五种情况。 */
function parseSubscription(value: unknown): ResourceServiceSubscription | null {
  if (!isRecord(value)) return null
  switch (value.kind) {
    case 'expires_at':
      return typeof value.expires_at === 'string' ? { kind: 'expires_at', expires_at: value.expires_at } : { kind: 'unknown' }
    case 'remaining':
      return isFiniteNumber(value.remaining_seconds) && typeof value.as_of === 'string'
        ? { kind: 'remaining', remaining_seconds: value.remaining_seconds, as_of: value.as_of }
        : { kind: 'unknown' }
    case 'permanent':
    case 'none':
      return { kind: value.kind }
    default:
      return { kind: 'unknown' }
  }
}

function parseField(value: unknown): ResourceServiceSnapshotField | null {
  if (!isRecord(value) || typeof value.key !== 'string' || typeof value.label !== 'string') return null
  const base = { key: value.key, label: value.label }
  switch (value.type) {
    case 'text':
    case 'status':
    case 'datetime':
      return typeof value.value === 'string' ? { ...base, type: value.type, value: value.value } : null
    case 'url':
      return isHttpsUrl(value.value) ? { ...base, type: 'url', value: value.value } : null
    case 'number':
    case 'duration':
      return isFiniteNumber(value.value) ? { ...base, type: value.type, value: value.value } : null
    case 'boolean':
      return typeof value.value === 'boolean' ? { ...base, type: 'boolean', value: value.value } : null
    default:
      return null
  }
}

export function parseResourceServiceSnapshot(value: unknown): ResourceServiceSnapshot | null {
  if (!isRecord(value)) return null
  const fields = Array.isArray(value.fields)
    ? value.fields.map(parseField).filter((field): field is ResourceServiceSnapshotField => field !== null)
    : []
  return {
    uid: optionalString(value.uid),
    account: optionalString(value.account),
    name: optionalString(value.name),
    status: parseAccountStatus(value.status),
    subscription: parseSubscription(value.subscription),
    fields,
    fetched_at: optionalString(value.fetched_at),
  }
}
