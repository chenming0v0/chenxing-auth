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
