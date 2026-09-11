export type ManagedAccountProvider = {
  slug: string
  name: string
  adapter: 'cltermux'
  base_url: string
  allowed_client_ids: string[]
  enabled: boolean
  version: number
  outbound_token_configured: boolean
  inbound_token_configured: boolean
}

export type AccountProviderUpdate = Pick<ManagedAccountProvider,
  'slug' | 'name' | 'adapter' | 'base_url' | 'allowed_client_ids' | 'enabled'
> & {
  expected_version: number
  outbound_token?: string
  inbound_token?: string
}

export function isManagedAccountProvider(value: unknown): value is ManagedAccountProvider {
  if (!value || typeof value !== 'object') return false
  const item = value as Record<string, unknown>
  return typeof item.slug === 'string' && typeof item.name === 'string'
    && item.adapter === 'cltermux' && typeof item.base_url === 'string'
    && Array.isArray(item.allowed_client_ids) && item.allowed_client_ids.every((id) => typeof id === 'string')
    && typeof item.enabled === 'boolean' && Number.isSafeInteger(item.version) && Number(item.version) > 0
    && typeof item.outbound_token_configured === 'boolean' && typeof item.inbound_token_configured === 'boolean'
    && !('outbound_token' in item) && !('inbound_token' in item)
}
