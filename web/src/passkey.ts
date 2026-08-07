/**
 * WebAuthn 编解码边界。后端以 base64url 传输 challenge、credential id 和
 * attestation/assertion 字节流，浏览器 API 只接受 BufferSource，因此注册与
 * 认证两条链路共用同一套解析规则，避免任一侧出现宽松解码。
 */

import { ApiError } from './api'

export type PasskeyChallenge = { publicKey?: Record<string, unknown> }

const INVALID_CHALLENGE = 'Passkey challenge is invalid'
const UNAVAILABLE_CREDENTIAL = 'Passkey credential is unavailable'
const PASSKEY_FAILED = 'Passkey 操作失败，请重试。'
const USER_VERIFICATION = ['required', 'preferred', 'discouraged']
const ATTESTATION = ['none', 'indirect', 'direct', 'enterprise']
const AUTHENTICATOR_TRANSPORTS = ['ble', 'hybrid', 'internal', 'nfc', 'usb'] as const satisfies readonly AuthenticatorTransport[]

function isAuthenticatorTransport(value: unknown): value is AuthenticatorTransport {
  return typeof value === 'string' && AUTHENTICATOR_TRANSPORTS.some((transport) => transport === value)
}

/**
 * 本模块自身抛出的哨兵消息到用户文案的映射。只有这些由代码写死的消息才允许
 * 参与文案决策，浏览器或其他来源的 message 一律走兜底。使用 Map 而非对象字面量，
 * 避免 constructor / __proto__ 之类的键命中 Object.prototype 上的成员。
 */
const INTERNAL_MESSAGES = new Map<string, string>([
  [INVALID_CHALLENGE, '服务返回的 Passkey challenge 无效，请重新登录。'],
  [UNAVAILABLE_CREDENTIAL, '当前设备没有可用的 Passkey 凭据，请重试或改用其他方式登录。'],
])

export function supportsWebAuthnGet(): boolean {
  return hasCredentialApi() && typeof navigator.credentials?.get === 'function'
}

export function supportsWebAuthnCreate(): boolean {
  return hasCredentialApi() && typeof navigator.credentials?.create === 'function'
}

function hasCredentialApi(): boolean {
  return typeof window !== 'undefined' && 'PublicKeyCredential' in window
}

export function decodeBase64Url(value: unknown): ArrayBuffer {
  if (typeof value !== 'string') throw new Error(INVALID_CHALLENGE)
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  if (normalized.length % 4 === 1) throw new Error(INVALID_CHALLENGE)
  try {
    const binary = atob(normalized.padEnd(normalized.length + ((4 - normalized.length % 4) % 4), '='))
    return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer
  } catch {
    throw new Error(INVALID_CHALLENGE)
  }
}

export function encodeBase64Url(value: ArrayBuffer): string {
  const bytes = new Uint8Array(value)
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('')
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function publicKeyOf(options: PasskeyChallenge): Record<string, unknown> {
  if (!options.publicKey || typeof options.publicKey !== 'object') throw new Error(INVALID_CHALLENGE)
  return options.publicKey
}

function decodeDescriptor(value: unknown): PublicKeyCredentialDescriptor {
  if (!value || typeof value !== 'object') throw new Error(INVALID_CHALLENGE)
  const descriptor = value as Record<string, unknown>
  if (descriptor.type !== 'public-key') throw new Error(INVALID_CHALLENGE)
  const transports = Array.isArray(descriptor.transports)
    ? descriptor.transports.filter(isAuthenticatorTransport)
    : []
  return {
    type: 'public-key',
    id: decodeBase64Url(descriptor.id),
    ...(transports.length > 0 ? { transports } : {}),
  }
}

function decodeCredParam(value: unknown): PublicKeyCredentialParameters {
  if (!value || typeof value !== 'object') throw new Error(INVALID_CHALLENGE)
  const param = value as Record<string, unknown>
  if (typeof param.alg !== 'number') throw new Error(INVALID_CHALLENGE)
  return { type: 'public-key', alg: param.alg }
}

function optionalUserVerification(value: unknown) {
  return USER_VERIFICATION.includes(String(value))
    ? { userVerification: value as UserVerificationRequirement }
    : {}
}

export function decodeRequestOptions(options: PasskeyChallenge): PublicKeyCredentialRequestOptions {
  const raw = publicKeyOf(options)
  const allowCredentials = Array.isArray(raw.allowCredentials)
    ? raw.allowCredentials.map(decodeDescriptor)
    : undefined
  return {
    challenge: decodeBase64Url(raw.challenge),
    ...(typeof raw.timeout === 'number' ? { timeout: raw.timeout } : {}),
    ...(typeof raw.rpId === 'string' ? { rpId: raw.rpId } : {}),
    ...(allowCredentials ? { allowCredentials } : {}),
    ...optionalUserVerification(raw.userVerification),
  }
}

export function decodeCreationOptions(options: PasskeyChallenge): PublicKeyCredentialCreationOptions {
  const raw = publicKeyOf(options)
  const rp = raw.rp as Record<string, unknown> | undefined
  const user = raw.user as Record<string, unknown> | undefined
  if (!rp || typeof rp.id !== 'string' || typeof rp.name !== 'string') throw new Error(INVALID_CHALLENGE)
  if (!user || typeof user.name !== 'string' || typeof user.displayName !== 'string') throw new Error(INVALID_CHALLENGE)
  if (!Array.isArray(raw.pubKeyCredParams) || raw.pubKeyCredParams.length === 0) throw new Error(INVALID_CHALLENGE)
  const selection = raw.authenticatorSelection as Record<string, unknown> | undefined
  return {
    rp: { id: rp.id, name: rp.name },
    user: { id: decodeBase64Url(user.id), name: user.name, displayName: user.displayName },
    challenge: decodeBase64Url(raw.challenge),
    pubKeyCredParams: raw.pubKeyCredParams.map(decodeCredParam),
    ...(typeof raw.timeout === 'number' ? { timeout: raw.timeout } : {}),
    ...(Array.isArray(raw.excludeCredentials)
      ? { excludeCredentials: raw.excludeCredentials.map(decodeDescriptor) }
      : {}),
    ...(selection ? { authenticatorSelection: decodeSelection(selection) } : {}),
    ...(ATTESTATION.includes(String(raw.attestation))
      ? { attestation: raw.attestation as AttestationConveyancePreference }
      : {}),
    // 未知扩展由浏览器自行忽略，这里原样透传后端要求的 credProtect/credProps。
    ...(raw.extensions && typeof raw.extensions === 'object'
      ? { extensions: raw.extensions as AuthenticationExtensionsClientInputs }
      : {}),
  }
}

function decodeSelection(selection: Record<string, unknown>): AuthenticatorSelectionCriteria {
  const attachment = selection.authenticatorAttachment
  const residentKey = selection.residentKey
  return {
    ...(attachment === 'platform' || attachment === 'cross-platform'
      ? { authenticatorAttachment: attachment }
      : {}),
    ...(['required', 'preferred', 'discouraged'].includes(String(residentKey))
      ? { residentKey: residentKey as ResidentKeyRequirement }
      : {}),
    ...(typeof selection.requireResidentKey === 'boolean'
      ? { requireResidentKey: selection.requireResidentKey }
      : {}),
    ...optionalUserVerification(selection.userVerification),
  }
}

export function serializeAssertion(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    response: {
      authenticatorData: encodeBase64Url(response.authenticatorData),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      signature: encodeBase64Url(response.signature),
      userHandle: response.userHandle ? encodeBase64Url(response.userHandle) : null,
    },
    type: credential.type,
  }
}

export function serializeAttestation(credential: PublicKeyCredential) {
  const response = credential.response as AuthenticatorAttestationResponse
  const transports = typeof response.getTransports === 'function' ? response.getTransports() : []
  return {
    id: credential.id,
    rawId: encodeBase64Url(credential.rawId),
    response: {
      attestationObject: encodeBase64Url(response.attestationObject),
      clientDataJSON: encodeBase64Url(response.clientDataJSON),
      // transports 影响后端保存的凭据元数据；缺失时不发送空数组，交由后端保持 None。
      ...(transports.length > 0 ? { transports } : {}),
    },
    type: credential.type,
  }
}

export function assertPublicKeyCredential(credential: Credential | null): PublicKeyCredential {
  if (!credential || credential.type !== 'public-key') throw new Error(UNAVAILABLE_CREDENTIAL)
  return credential as PublicKeyCredential
}

/**
 * 把 Passkey 链路上的任意异常映射为用户可见文案。
 *
 * 浏览器 DOMException 的 message 会包含 RP ID、origin 和认证器细节，例如
 * "The relying party ID 'auth.example.com' is not a registrable domain suffix..."，
 * 直接展示等于把部署拓扑写到登录页上。因此除了 AbortError / NotAllowedError /
 * InvalidStateError 三个需要区分引导语的类型，其余 DOMException 一律兜底；
 * 其他 Error 只在消息属于本模块哨兵或已经过 safeErrorMessage 清洗的 ApiError 时透传。
 */
export function passkeyErrorMessage(error: unknown): string {
  if (typeof DOMException !== 'undefined' && error instanceof DOMException) {
    if (error.name === 'AbortError' || error.name === 'NotAllowedError') return 'Passkey 操作已取消，请重试。'
    if (error.name === 'InvalidStateError') return '该设备已经绑定过 Passkey，请直接使用它登录。'
    return PASSKEY_FAILED
  }
  // ApiError 的 message 由 api.ts 的 safeErrorMessage 生成，本身不含内部细节。
  if (error instanceof ApiError) return error.message
  if (error instanceof Error) return INTERNAL_MESSAGES.get(error.message) ?? PASSKEY_FAILED
  return PASSKEY_FAILED
}
