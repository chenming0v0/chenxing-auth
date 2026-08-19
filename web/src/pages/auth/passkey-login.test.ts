import { beforeEach, describe, expect, it, vi } from 'vitest'
import { apiFetch } from '../../api'
import { loginWithDiscoverablePasskey } from './passkey-login'

vi.mock('../../api', () => ({
  apiFetch: vi.fn(),
}))

const mockedApiFetch = vi.mocked(apiFetch)

function assertionCredential(): PublicKeyCredential {
  const bytes = new Uint8Array([1, 2, 3])
  return {
    id: 'credential-id',
    rawId: bytes.buffer,
    type: 'public-key',
    response: {
      authenticatorData: bytes.buffer,
      clientDataJSON: bytes.buffer,
      signature: bytes.buffer,
      userHandle: null,
    } as AuthenticatorAssertionResponse,
    getClientExtensionResults: () => ({}),
  } as unknown as PublicKeyCredential
}

describe('discoverable Passkey login', () => {
  beforeEach(() => {
    mockedApiFetch.mockReset()
    Object.defineProperty(window, 'PublicKeyCredential', { value: class {}, configurable: true })
    Object.defineProperty(navigator, 'credentials', {
      configurable: true,
      value: { get: vi.fn().mockResolvedValue(assertionCredential()) },
    })
  })

  it('returns a pending TOTP response instead of assuming the session is complete', async () => {
    const pending = { status: 'factor_required', methods: ['totp'] }
    mockedApiFetch
      .mockResolvedValueOnce({
        challenge_id: 'challenge-id',
        options: { publicKey: { challenge: 'AQ', userVerification: 'required' } },
      })
      .mockResolvedValueOnce(pending)

    const onPending = vi.fn()
    const onComplete = vi.fn().mockResolvedValue(undefined)
    await loginWithDiscoverablePasskey(onPending, onComplete)

    expect(onPending).toHaveBeenCalledWith(pending)
    expect(onComplete).not.toHaveBeenCalled()
  })
})
