export type AccountPortalPublicProvider = {
  id: string
  display_name: string
  issuer: string
  identifier_label: string
  secret_label: string
  identifier_sensitive: boolean
}

export type AccountPortalAdminProvider = AccountPortalPublicProvider & {
  client_id: string
  enabled: boolean
  revision: number
  identity_locked: boolean
}

export type AccountPortalBinding = {
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

export type AccountPortalProviderInput = {
  display_name: string
  issuer: string
  client_id: string
  client_secret?: string
  expected_revision: number
}

export type AccountPortalBindingCreateInput = {
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

const SECRET_FIELDS = ['client_secret', 'token', 'access_token', 'refresh_token', 'token_bundle_ciphertext']

function hasNoSecrets(value: Record<string, unknown>): boolean {
  return SECRET_FIELDS.every((field) => !(field in value))
}

export function isAccountPortalPublicProvider(value: unknown): value is AccountPortalPublicProvider {
  if (!isRecord(value) || !hasNoSecrets(value)) return false
  return typeof value.id === 'string'
    && typeof value.display_name === 'string'
    && typeof value.issuer === 'string'
    && typeof value.identifier_label === 'string'
    && typeof value.secret_label === 'string'
    && typeof value.identifier_sensitive === 'boolean'
}

export function isAccountPortalAdminProvider(value: unknown): value is AccountPortalAdminProvider {
  if (!isAccountPortalPublicProvider(value) || !isRecord(value)) return false
  const item = value as Record<string, unknown>
  return typeof item.client_id === 'string'
    && typeof item.enabled === 'boolean'
    && Number.isSafeInteger(item.revision)
    && Number(item.revision) >= 1
    && typeof item.identity_locked === 'boolean'
}

export function isAccountPortalBinding(value: unknown): value is AccountPortalBinding {
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

export function isAccountPortalAdminProviderList(value: unknown): value is AccountPortalAdminProvider[] {
  return Array.isArray(value) && value.every(isAccountPortalAdminProvider)
}

export function isAccountPortalPublicProviderList(value: unknown): value is AccountPortalPublicProvider[] {
  return Array.isArray(value) && value.every(isAccountPortalPublicProvider)
}

export function isAccountPortalBindingList(value: unknown): value is AccountPortalBinding[] {
  return Array.isArray(value) && value.every(isAccountPortalBinding)
}
