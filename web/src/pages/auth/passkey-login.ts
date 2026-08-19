import { apiFetch, type LoginResponse, type PendingLoginResponse } from '../../api'
import {
  assertPublicKeyCredential,
  decodeRequestOptions,
  serializeAssertion,
  type PasskeyChallenge,
} from '../../passkey'

export async function loginWithDiscoverablePasskey(
  onPending: (pending: PendingLoginResponse) => void,
  onComplete: () => Promise<void>,
): Promise<void> {
  const start = await apiFetch<{ challenge_id: string; options: PasskeyChallenge }>(
    '/api/v1/auth/passkeys/discoverable/start',
    { method: 'POST', redirectOn401: false, csrf: 'pre-session', body: JSON.stringify({}) },
  )
  const credential = assertPublicKeyCredential(
    await navigator.credentials.get({ publicKey: decodeRequestOptions(start.options) }),
  )
  const response = await apiFetch<LoginResponse | PendingLoginResponse>('/api/v1/auth/passkeys/discoverable/finish', {
    method: 'POST',
    redirectOn401: false,
    csrf: 'pre-session',
    body: JSON.stringify({
      challenge_id: start.challenge_id,
      credential: serializeAssertion(credential),
    }),
  })
  if ('status' in response && 'methods' in response) {
    onPending(response)
    return
  }
  await onComplete()
}
