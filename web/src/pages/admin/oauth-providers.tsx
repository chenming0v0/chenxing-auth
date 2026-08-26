import { useState } from 'react'
import { ConsoleLayout } from '../../components/shells'
import { Notice, PageIntro } from '../../components/ui'
import { AdminGate, useAdminAccess } from './shared'
import { useDraftLeaveGuard, useFlashMessage } from './settings/panel'
import { OAuthProvidersPanel } from './settings/oauth-providers-panel'

export function AdminOAuthProviders() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <AdminGate access={access} permission="manage_identity_providers">
        <OAuthProvidersPageBody />
      </AdminGate>
    </ConsoleLayout>
  )
}

export function OAuthProvidersPageBody() {
  const { flash, message } = useFlashMessage()
  const [dirty, setDirty] = useState(false)
  useDraftLeaveGuard(dirty)
  return (
    <>
      <PageIntro
        eyebrow="// Admin · Identity"
        title="身份提供商"
        description="接入自定义 OAuth 2.0 + UserInfo 外部登录。这不是 OIDC：身份字段只取自 UserInfo 响应，本平台不验证 ID Token。"
      />
      {message ? <div className="mb-6"><Notice tone={message.tone}>{message.text}</Notice></div> : null}
      <OAuthProvidersPanel onMessage={flash} onDirtyChange={setDirty} />
    </>
  )
}
