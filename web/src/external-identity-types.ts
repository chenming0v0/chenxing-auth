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
