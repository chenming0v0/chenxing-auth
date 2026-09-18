import { apiFetch } from './api'
import type {
  AccountPortalAdminProvider,
  AccountPortalBinding,
  AccountPortalBindingCreateInput,
  AccountPortalProviderInput,
  AccountPortalPublicProvider,
} from './account-portal-types'

export type * from './account-portal-types'

const ADMIN = '/api/v1/admin/account-portal/providers'
const AUTH = '/api/v1/auth/account-portal'

export function newPortalIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function listAccountPortalAdminProviders(): Promise<AccountPortalAdminProvider[]> {
  return apiFetch<AccountPortalAdminProvider[]>(ADMIN, { redirectOn401: false })
}

export function createAccountPortalAdminProvider(
  input: AccountPortalProviderInput,
): Promise<AccountPortalAdminProvider> {
  return apiFetch<AccountPortalAdminProvider>(ADMIN, {
    method: 'POST',
    redirectOn401: false,
    body: JSON.stringify(input),
  })
}

export function updateAccountPortalAdminProvider(
  id: string,
  input: AccountPortalProviderInput,
): Promise<AccountPortalAdminProvider> {
  return apiFetch<AccountPortalAdminProvider>(`${ADMIN}/${encodeURIComponent(id)}`, {
    method: 'PUT',
    redirectOn401: false,
    body: JSON.stringify(input),
  })
}

export function setAccountPortalAdminProviderEnabled(
  id: string,
  enabled: boolean,
): Promise<AccountPortalAdminProvider> {
  const action = enabled ? 'enable' : 'disable'
  return apiFetch<AccountPortalAdminProvider>(`${ADMIN}/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    redirectOn401: false,
  })
}

export function listAccountPortalProviders(): Promise<AccountPortalPublicProvider[]> {
  return apiFetch<AccountPortalPublicProvider[]>(`${AUTH}/providers`, { redirectOn401: false })
}

export function listAccountPortalBindings(): Promise<AccountPortalBinding[]> {
  return apiFetch<AccountPortalBinding[]>(`${AUTH}/bindings`, { redirectOn401: false })
}

export function createAccountPortalBinding(
  input: AccountPortalBindingCreateInput,
  idempotencyKey: string,
): Promise<AccountPortalBinding> {
  return apiFetch<AccountPortalBinding>(`${AUTH}/bindings`, {
    method: 'POST',
    redirectOn401: false,
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
}

export function refreshAccountPortalBinding(
  id: string,
  idempotencyKey: string,
): Promise<AccountPortalBinding> {
  return apiFetch<AccountPortalBinding>(`${AUTH}/bindings/${encodeURIComponent(id)}/refresh`, {
    method: 'POST',
    redirectOn401: false,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function syncAccountPortalBinding(id: string): Promise<AccountPortalBinding> {
  return apiFetch<AccountPortalBinding>(`${AUTH}/bindings/${encodeURIComponent(id)}/sync`, {
    method: 'POST',
    redirectOn401: false,
  })
}

export function unlinkAccountPortalBinding(id: string): Promise<void> {
  return apiFetch<void>(`${AUTH}/bindings/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    redirectOn401: false,
  })
}
