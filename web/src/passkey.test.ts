import { describe, expect, it } from 'vitest'
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
    expect(() => decodeBase64Url(123)).toThrow('Passkey challenge is invalid')
  })

  it('encodes ArrayBuffer to base64url', () => {
    const buffer = new Uint8Array([1, 2, 3, 4]).buffer
    expect(encodeBase64Url(buffer)).toBe('AQIDBA')
  })

  it('decodes authentication request options', () => {
    const challenge: PasskeyChallenge = {
      publicKey: {
        challenge: 'AQIDBA',
        rpId: 'example.com',
        timeout: 60000,
        allowCredentials: [{ type: 'public-key', id: 'Y3JlZA' }],
        userVerification: 'required',
      },
    }
    const options = decodeRequestOptions(challenge)
    expect(options.rpId).toBe('example.com')
    expect(options.timeout).toBe(60000)
    expect(options.userVerification).toBe('required')
    expect(options.allowCredentials).toHaveLength(1)
    expect(options.allowCredentials![0].type).toBe('public-key')
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

  it('provides user-friendly error messages', () => {
    const abortError = new DOMException('User canceled', 'AbortError')
    expect(passkeyErrorMessage(abortError)).toContain('已取消')
    const invalidState = new DOMException('Credential excluded', 'InvalidStateError')
    expect(passkeyErrorMessage(invalidState)).toContain('已经绑定过')
    const generic = new Error('Network error')
    expect(passkeyErrorMessage(generic)).toBe('Network error')
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

  it('serializes an attestation response and omits empty transports', () => {
    const base = {
      id: 'cred-2',
      rawId: new Uint8Array([1, 2]).buffer,
      type: 'public-key',
      response: {
        attestationObject: new Uint8Array([3, 4]).buffer,
        clientDataJSON: new Uint8Array([5, 6]).buffer,
        getTransports: () => [],
      },
    } as unknown as PublicKeyCredential
    expect(serializeAttestation(base).response).toEqual({
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
