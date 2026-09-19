import { apiFetch } from './api'
import type {
  ResourceServiceAdminProvider,
  ResourceServiceBinding,
  ResourceServiceBindingCreateInput,
  ResourceServiceProviderInput,
  ResourceServicePublicProvider,
} from './resource-services-types'

export type * from './resource-services-types'

const ADMIN = '/api/v1/admin/resource-services'
const AUTH = '/api/v1/auth/resource-services'

export function newResourceServiceIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256))
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('')
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`
}

export function listResourceServiceAdminProviders(): Promise<ResourceServiceAdminProvider[]> {
  return apiFetch<ResourceServiceAdminProvider[]>(ADMIN, { redirectOn401: false })
}

export function createResourceServiceAdminProvider(
  input: ResourceServiceProviderInput,
): Promise<ResourceServiceAdminProvider> {
  return apiFetch<ResourceServiceAdminProvider>(ADMIN, {
    method: 'POST',
    redirectOn401: false,
    body: JSON.stringify(input),
  })
}

export function updateResourceServiceAdminProvider(
  id: string,
  input: ResourceServiceProviderInput,
): Promise<ResourceServiceAdminProvider> {
  return apiFetch<ResourceServiceAdminProvider>(`${ADMIN}/${encodeURIComponent(id)}`, {
    method: 'PUT',
    redirectOn401: false,
    body: JSON.stringify(input),
  })
}

export function setResourceServiceAdminProviderEnabled(
  id: string,
  enabled: boolean,
): Promise<ResourceServiceAdminProvider> {
  const action = enabled ? 'enable' : 'disable'
  return apiFetch<ResourceServiceAdminProvider>(`${ADMIN}/${encodeURIComponent(id)}/${action}`, {
    method: 'POST',
    redirectOn401: false,
  })
}

export function listResourceServiceProviders(): Promise<ResourceServicePublicProvider[]> {
  return apiFetch<ResourceServicePublicProvider[]>(AUTH, { redirectOn401: false })
}

export function listResourceServiceBindings(): Promise<ResourceServiceBinding[]> {
  return apiFetch<ResourceServiceBinding[]>(`${AUTH}/bindings`, { redirectOn401: false })
}

export function createResourceServiceBinding(
  input: ResourceServiceBindingCreateInput,
  idempotencyKey: string,
): Promise<ResourceServiceBinding> {
  return apiFetch<ResourceServiceBinding>(`${AUTH}/bindings`, {
    method: 'POST',
    redirectOn401: false,
    headers: { 'Idempotency-Key': idempotencyKey },
    body: JSON.stringify(input),
  })
}

export function refreshResourceServiceBinding(
  id: string,
  idempotencyKey: string,
): Promise<ResourceServiceBinding> {
  return apiFetch<ResourceServiceBinding>(`${AUTH}/bindings/${encodeURIComponent(id)}/refresh`, {
    method: 'POST',
    redirectOn401: false,
    headers: { 'Idempotency-Key': idempotencyKey },
  })
}

export function syncResourceServiceBinding(id: string): Promise<ResourceServiceBinding> {
  return apiFetch<ResourceServiceBinding>(`${AUTH}/bindings/${encodeURIComponent(id)}/sync`, {
    method: 'POST',
    redirectOn401: false,
  })
}

export function unlinkResourceServiceBinding(id: string): Promise<void> {
  return apiFetch<void>(`${AUTH}/bindings/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    redirectOn401: false,
  })
}
