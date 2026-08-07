import { describe, expect, it } from 'vitest'
import { ApiError } from './api'
import {
  decodeBase64Url, encodeBase64Url, decodeRequestOptions, decodeCreationOptions,
  serializeAssertion, serializeAttestation, passkeyErrorMessage, assertPublicKeyCredential,
  type PasskeyChallenge,
} from './passkey'

describe('passkey codec', () => {
  it('decodes valid base64url', () => {
    const decoded = decodeBase64Url('AQIDBA')
    expect(new Uint8Array(decoded)).toEqual(new Uint8Array([1, 2, 3, 4]))
  })

  it('rejects invalid base64url', () => {
    expect(() => decodeBase64Url('invalid!@#')).toThrow('Passkey challenge is invalid')
    for (const value of [undefined, null, 123, {}, []]) {
      expect(() => decodeBase64Url(value)).toThrow('Passkey challenge is invalid')
    }
  })

  it('rejects base64url lengths with an impossible remainder', () => {
    for (const value of ['A', 'AQIDA']) {
      expect(value.length % 4).toBe(1)
      expect(() => decodeBase64Url(value)).toThrow('Passkey challenge is invalid')
    }
  })

  it('encodes ArrayBuffer to base64url', () => {
    const buffer = new Uint8Array([1, 2, 3, 4]).buffer
    expect(encodeBase64Url(buffer)).toBe('AQIDBA')
  })

  it('round-trips every byte value through encode/decode', () => {
    // 覆盖 0x00-0xff 全字节域，长度 256 % 3 === 1，同时验证最长的补位分支。
    const original = new Uint8Array(256)
    for (let index = 0; index < original.length; index += 1) original[index] = index
    expect(new Uint8Array(decodeBase64Url(encodeBase64Url(original.buffer)))).toEqual(original)
  })

  it('round-trips at every padding remainder and on empty input', () => {
    // 长度 % 3 决定编码尾部补位数量（0 / 1 / 2 个 '='），三条分支都要走到。
    for (const length of [0, 1, 2, 3, 4, 5]) {
      const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + 11) & 0xff)
      const encoded = encodeBase64Url(bytes.buffer)
      expect(encoded).not.toMatch(/[+/=]/)
      expect(new Uint8Array(decodeBase64Url(encoded))).toEqual(bytes)
    }
  })

  it('encodes bytes that map to + and / as - and _', () => {
    // 0xfb 0xff 0xbf 的标准 base64 是 '+/+/'，base64url 必须替换成 '-_-_'。
    // 这是 base64url 与 base64 的唯一差别，缺了这条断言替换规则就没被验证。
    const bytes = new Uint8Array([0xfb, 0xff, 0xbf])
    expect(btoa(String.fromCharCode(...bytes))).toBe('+/+/')
    expect(encodeBase64Url(bytes.buffer)).toBe('-_-_')
  })

  it('decodes - and _ back to the bytes standard base64 spells with + and /', () => {
    expect(new Uint8Array(decodeBase64Url('-_-_'))).toEqual(new Uint8Array([0xfb, 0xff, 0xbf]))
    // 单独验证两个替换字符各自的方向，避免只有对称写错时互相掩盖。
    expect(new Uint8Array(decodeBase64Url('-w'))).toEqual(new Uint8Array([0xfb]))
    expect(new Uint8Array(decodeBase64Url('_w'))).toEqual(new Uint8Array([0xff]))
  })

  it('round-trips a base64url string that contains both - and _', () => {
    const source = '-_-_AQIDBA'
    expect(encodeBase64Url(decodeBase64Url(source))).toBe(source)
  })

  it('decodes authentication request options', () => {
    const challenge: PasskeyChallenge = {
      publicKey: {
        challenge: 'AQIDBA',
        rpId: 'example.com',
        timeout: 60000,
        allowCredentials: [{
          type: 'public-key',
          id: 'Y3JlZA',
          transports: ['usb', 'unknown', 123, 'internal'],
        }],
        userVerification: 'required',
      },
    }
    const options = decodeRequestOptions(challenge)
    expect(options.rpId).toBe('example.com')
    expect(options.timeout).toBe(60000)
    expect(options.userVerification).toBe('required')
    expect(options.allowCredentials).toHaveLength(1)
    expect(options.allowCredentials![0].type).toBe('public-key')
    expect(options.allowCredentials![0].transports).toEqual(['usb', 'internal'])
  })

  it('omits absent credential transports', () => {
    const options = decodeRequestOptions({
      publicKey: { challenge: 'AQIDBA', allowCredentials: [{ type: 'public-key', id: 'Y3JlZA' }] },
    })
    expect('transports' in options.allowCredentials![0]).toBe(false)
  })

  it('omits credential transports when the array has no valid values', () => {
    const options = decodeRequestOptions({
      publicKey: {
        challenge: 'AQIDBA',
        allowCredentials: [
          { type: 'public-key', id: 'Y3JlZA', transports: [] },
          { type: 'public-key', id: 'Y3JlZA', transports: ['unknown', 123] },
        ],
      },
    })
    expect(options.allowCredentials).toHaveLength(2)
    expect('transports' in options.allowCredentials![0]).toBe(false)
    expect('transports' in options.allowCredentials![1]).toBe(false)
  })

  it('rejects request options without a challenge', () => {
    expect(() => decodeRequestOptions({ publicKey: {} })).toThrow('Passkey challenge is invalid')
    expect(() => decodeRequestOptions({ publicKey: { rpId: 'example.com' } }))
      .toThrow('Passkey challenge is invalid')
    for (const challenge of [undefined, null, 123, {}, [], 'invalid!@#']) {
      expect(() => decodeRequestOptions({ publicKey: { challenge } }))
        .toThrow('Passkey challenge is invalid')
    }
    expect(() => decodeRequestOptions({
      publicKey: { challenge: 'AQIDBA', allowCredentials: [{ type: 'not-public-key', id: 'Y3JlZA' }] },
    })).toThrow('Passkey challenge is invalid')
    expect(() => decodeRequestOptions({})).toThrow('Passkey challenge is invalid')
  })

  it('drops unknown userVerification values instead of forwarding them', () => {
    const options = decodeRequestOptions({ publicKey: { challenge: 'AQIDBA', userVerification: 'sometimes' } })
    expect(options.userVerification).toBeUndefined()
  })

  it('decodes creation options with user and rp', () => {
    const challenge: PasskeyChallenge = {
      publicKey: {
        rp: { id: 'example.com', name: 'Example' },
        user: { id: 'dXNlcg', name: 'user@example.com', displayName: 'User' },
        challenge: 'AQIDBA',
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          residentKey: 'required',
          requireResidentKey: true,
          userVerification: 'required',
        },
        attestation: 'none',
      },
    }
    const options = decodeCreationOptions(challenge)
    expect(options.rp.id).toBe('example.com')
    expect(options.user.name).toBe('user@example.com')
    expect(options.pubKeyCredParams).toHaveLength(1)
    expect(options.attestation).toBe('none')
    expect(options.authenticatorSelection?.authenticatorAttachment).toBe('platform')
  })

  it('rejects creation options missing required fields', () => {
    expect(() => decodeCreationOptions({ publicKey: {} })).toThrow('Passkey challenge is invalid')
    expect(() => decodeCreationOptions({ publicKey: { rp: {} } })).toThrow('Passkey challenge is invalid')
  })

  it('rejects malformed creation challenges after validating the other required fields', () => {
    const required = {
      rp: { id: 'example.com', name: 'Example' },
      user: { id: 'dXNlcg', name: 'user@example.com', displayName: 'User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    }
    for (const challenge of [undefined, null, 123, {}, [], 'invalid!@#']) {
      expect(() => decodeCreationOptions({ publicKey: { ...required, challenge } }))
        .toThrow('Passkey challenge is invalid')
    }
  })

  it('provides user-friendly error messages', () => {
    const abortError = new DOMException('User canceled', 'AbortError')
    expect(passkeyErrorMessage(abortError)).toContain('已取消')
    expect(passkeyErrorMessage(new DOMException('No allowed', 'NotAllowedError'))).toContain('已取消')
    const invalidState = new DOMException('Credential excluded', 'InvalidStateError')
    expect(passkeyErrorMessage(invalidState)).toContain('已经绑定过')
    expect(passkeyErrorMessage(new Error('Passkey challenge is invalid'))).toContain('challenge 无效')
    expect(passkeyErrorMessage(new Error('Passkey credential is unavailable'))).toContain('没有可用的 Passkey 凭据')
  })

  it('never leaks rp id or origin from unexpected DOMExceptions', () => {
    // 浏览器在 RP ID 校验失败时会把部署域名写进 message，文案里不能出现它们。
    const securityError = new DOMException(
      "The relying party ID 'auth.example.com' is not a registrable domain suffix of, nor equal to 'https://app.example.com'",
      'SecurityError',
    )
    const message = passkeyErrorMessage(securityError)
    expect(message).toBe('Passkey 操作失败，请重试。')
    expect(message).not.toContain('auth.example.com')
    expect(message).not.toContain('app.example.com')
    expect(message).not.toContain('relying party')

    for (const name of ['NotSupportedError', 'ConstraintError', 'UnknownError', 'TimeoutError', 'DataError']) {
      const leaky = new DOMException("rp id 'auth.example.com' rejected at origin https://app.example.com", name)
      expect(passkeyErrorMessage(leaky)).toBe('Passkey 操作失败，请重试。')
    }
  })

  it('falls back for arbitrary Error messages and non-Error throws', () => {
    // 普通 Error 的 message 可能来自任意第三方代码，一律走兜底而不是原样展示。
    expect(passkeyErrorMessage(new Error('connect ECONNREFUSED 10.0.0.7:5432'))).toBe('Passkey 操作失败，请重试。')
    expect(passkeyErrorMessage(new TypeError("Cannot read properties of undefined (reading 'rpId')")))
      .toBe('Passkey 操作失败，请重试。')
    expect(passkeyErrorMessage('rp id auth.example.com')).toBe('Passkey 操作失败，请重试。')
    expect(passkeyErrorMessage(undefined)).toBe('Passkey 操作失败，请重试。')
    expect(passkeyErrorMessage({ message: 'auth.example.com' })).toBe('Passkey 操作失败，请重试。')
  })

  it('keeps the already sanitized ApiError message', () => {
    // ApiError 的 message 由 api.ts 的 safeErrorMessage 产出，透传不会泄露内部细节，
    // 且能保留 passkey_disabled 这类后端错误码对应的具体引导。
    const disabled = new ApiError('Passkey 登录尚未启用。', 400, 'passkey_disabled')
    expect(passkeyErrorMessage(disabled)).toBe('Passkey 登录尚未启用。')
  })

  it('resists prototype pollution through internal message lookup', () => {
    // message 参与查表，必须确保 Object.prototype 上的键不会被当成文案返回。
    for (const message of ['constructor', '__proto__', 'toString', 'valueOf', 'hasOwnProperty']) {
      const result = passkeyErrorMessage(new Error(message))
      expect(typeof result).toBe('string')
      expect(result).toBe('Passkey 操作失败，请重试。')
    }
  })

  it('serializes an assertion response as base64url', () => {
    const credential = {
      id: 'cred-1',
      rawId: new Uint8Array([1, 2, 3, 4]).buffer,
      type: 'public-key',
      response: {
        authenticatorData: new Uint8Array([5, 6]).buffer,
        clientDataJSON: new Uint8Array([7, 8]).buffer,
        signature: new Uint8Array([9, 10]).buffer,
        userHandle: null,
      },
    } as unknown as PublicKeyCredential
    expect(serializeAssertion(credential)).toEqual({
      id: 'cred-1',
      rawId: 'AQIDBA',
      response: {
        authenticatorData: 'BQY',
        clientDataJSON: 'Bwg',
        signature: 'CQo',
        userHandle: null,
      },
      type: 'public-key',
    })
  })

  it('serializes a non-null userHandle as base64url', () => {
    const credential = {
      id: 'cred-3',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      response: {
        authenticatorData: new Uint8Array([5, 6]).buffer,
        clientDataJSON: new Uint8Array([7, 8]).buffer,
        signature: new Uint8Array([9, 10]).buffer,
        // 可发现凭据会带回用户句柄，必须编码而不是丢成 null。
        userHandle: new Uint8Array([0xfb, 0xff, 0xbf]).buffer,
      },
    } as unknown as PublicKeyCredential
    const serialized = serializeAssertion(credential)
    expect(serialized.response.userHandle).toBe('-_-_')
    expect(new Uint8Array(decodeBase64Url(serialized.response.userHandle!)))
      .toEqual(new Uint8Array([0xfb, 0xff, 0xbf]))
  })

  it('treats an empty userHandle buffer as absent', () => {
    // ArrayBuffer 恒为 truthy，空缓冲会编码成空串而不是 null，锁定这一现状。
    const credential = {
      id: 'cred-4',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      response: {
        authenticatorData: new Uint8Array([5, 6]).buffer,
        clientDataJSON: new Uint8Array([7, 8]).buffer,
        signature: new Uint8Array([9, 10]).buffer,
        userHandle: new Uint8Array([]).buffer,
      },
    } as unknown as PublicKeyCredential
    expect(serializeAssertion(credential).response.userHandle).toBe('')
  })

  it('serializes an attestation response and handles optional transports', () => {
    const base = {
      id: 'cred-2',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      response: {
        attestationObject: new Uint8Array([3, 4]).buffer,
        clientDataJSON: new Uint8Array([5, 6]).buffer,
      },
    } as unknown as PublicKeyCredential
    expect(serializeAttestation(base).response).toEqual({
      attestationObject: 'AwQ',
      clientDataJSON: 'BQY',
    })

    const withEmptyTransports = {
      ...base,
      response: { ...base.response, getTransports: () => [] },
    } as unknown as PublicKeyCredential
    expect(serializeAttestation(withEmptyTransports).response).toEqual({
      attestationObject: 'AwQ',
      clientDataJSON: 'BQY',
    })

    const withTransports = {
      ...base,
      response: { ...base.response, getTransports: () => ['internal', 'hybrid'] },
    } as unknown as PublicKeyCredential
    expect(serializeAttestation(withTransports).response.transports).toEqual(['internal', 'hybrid'])
  })

  it('asserts PublicKeyCredential type', () => {
    const valid = { type: 'public-key', id: 'cred-1' } as Credential
    expect(assertPublicKeyCredential(valid)).toBe(valid)
    expect(() => assertPublicKeyCredential(null)).toThrow('Passkey credential is unavailable')
    const invalid = { type: 'password' } as Credential
    expect(() => assertPublicKeyCredential(invalid)).toThrow('Passkey credential is unavailable')
  })
})
