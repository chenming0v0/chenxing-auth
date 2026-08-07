import { apiFetch, type LoginResponse, type PendingLoginResponse } from '../../api'
import {
  assertPublicKeyCredential, decodeCreationOptions, decodeRequestOptions, passkeyErrorMessage,
  serializeAssertion, serializeAttestation, supportsWebAuthnCreate, supportsWebAuthnGet,
  type PasskeyChallenge,
} from '../../passkey'
import { Button, Notice } from '../../components/ui'

/**
 * 首次绑定走 registration，已绑定走 authentication。两条链路的差异只有
 * challenge 解码方向和序列化函数，因此共用同一个组件，由 register 决定分支。
 */
export function PasskeyStep({
  pending, register, busy, onComplete, onBusy, onMessage,
}: {
  pending: PendingLoginResponse
  register: boolean
  busy: boolean
  onComplete: () => Promise<void>
  onBusy: (value: boolean) => void
  onMessage: (value: string) => void
}) {
  async function run() {
    onMessage('')
    if (register ? !supportsWebAuthnCreate() : !supportsWebAuthnGet()) {
      onMessage('当前浏览器不支持 Passkey，请使用支持 WebAuthn 的浏览器。')
      return
    }
    onBusy(true)
    try {
      await (register ? registerPasskey() : authenticatePasskey())
      await onComplete()
    } catch (error) {
      onMessage(passkeyErrorMessage(error))
    } finally {
      onBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <Notice tone="info">
        {register
          ? '首次绑定 Passkey：确认后由本设备的生物识别或安全密钥创建凭据。'
          : '请使用已绑定的 Passkey 完成登录。'}
      </Notice>
      <Button type="button" icon="key-round" onClick={() => void run()} disabled={busy} className="w-full">
        {busy ? '处理中…' : register ? '创建并绑定 Passkey' : '使用 Passkey 登录'}
      </Button>
    </div>
  )
}

async function registerPasskey(): Promise<void> {
  const challenge = await apiFetch<PasskeyChallenge>('/api/v1/auth/passkeys/register/start', {
    method: 'POST', redirectOn401: false, body: JSON.stringify({}),
  })
  const publicKey = decodeCreationOptions(challenge)
  const credential = assertPublicKeyCredential(await navigator.credentials.create({ publicKey }))
  await apiFetch<LoginResponse>('/api/v1/auth/passkeys/register/finish', {
    method: 'POST', redirectOn401: false,
    body: JSON.stringify({ credential: serializeAttestation(credential) }),
  })
}

async function authenticatePasskey(): Promise<void> {
  const challenge = await apiFetch<PasskeyChallenge>('/api/v1/auth/passkeys/authentication/start', {
    method: 'POST', redirectOn401: false, body: JSON.stringify({}),
  })
  const publicKey = decodeRequestOptions(challenge)
  const credential = assertPublicKeyCredential(await navigator.credentials.get({ publicKey }))
  await apiFetch<LoginResponse>('/api/v1/auth/passkeys/authentication/finish', {
    method: 'POST', redirectOn401: false,
    body: JSON.stringify({ credential: serializeAssertion(credential) }),
  })
}
