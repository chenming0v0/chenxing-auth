import { useCallback, useMemo, useRef, useState } from 'react'
import { apiFetch, type KeyRotationResponse } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Button, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { AdminGate, useAdminAccess, type AdminAccess } from './shared'
import { EmailPolicyPanel } from './settings/email-policy-panel'
import { OAuthProvidersPanel } from './settings/oauth-providers-panel'
import { PasskeyPanel } from './settings/passkey-panel'
import { SecurityLimitsPanel } from './settings/security-limits-panel'
import { SessionLifetimePanel } from './settings/session-lifetime-panel'
import { SmtpPanel } from './settings/smtp-panel'
import { IssuerPanel } from './settings/issuer-panel'
import { RegistrationPanel } from './settings/registration-panel'
import { useDraftLeaveGuard, useFlashMessage } from './settings/panel'

export function AdminSettings() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Admin · System"
        title="系统设置"
        description="配置辰星认证中枢的登录、邮件与身份提供商。"
      />
      <p className="chenxing-caption mb-6 flex items-center gap-1.5 text-[var(--chenxing-warning)]">
        <Icon name="lock" size={14} />
        敏感凭证为只写字段，保存后不会回显；日志与列表均不返回明文或哈希。
      </p>
      <AdminGate access={access} permission="manage_settings">
        <SettingsWorkspace access={access} />
      </AdminGate>
    </ConsoleLayout>
  )
}

export function SettingsWorkspace({ access }: { access: AdminAccess }) {
  const [keyResult, setKeyResult] = useState<KeyRotationResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const canManageProviders = Boolean(access.data?.permissions.includes('manage_identity_providers'))
  const canRotateKeys = Boolean(access.data?.permissions.includes('rotate_keys'))
  /* flash 的引用跨渲染稳定，面板的加载 effect 不会因为消息状态变化而重跑（#268）。 */
  const { flash, message } = useFlashMessage()

  /* #381：聚合各面板的未保存草稿。每个面板拿到独立且跨渲染稳定的上报回调
     （useMemo 锁定工厂产物），回调闭包各自记住自己的脏标记，只在状态翻转时更新
     计数——「一块面板保存后」不会把其它面板的脏标记清掉。 */
  const dirtyCount = useRef(0)
  const [dirty, setDirty] = useState(false)
  const makeDirtyReporter = useCallback(() => {
    let mine = false
    return (isDirty: boolean) => {
      if (isDirty === mine) return
      mine = isDirty
      dirtyCount.current += isDirty ? 1 : -1
      setDirty(dirtyCount.current > 0)
    }
  }, [])
  const reportPasskeyDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportEmailPolicyDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSmtpDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSecurityLimitsDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSessionLifetimeDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportOAuthDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportIssuerDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportRegistrationDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const canManageIssuer = Boolean(access.data?.permissions.includes('manage_issuer'))
  /* 任一面板有草稿时，路由跳转与刷新/关页前都提示确认。 */
  useDraftLeaveGuard(dirty)

  async function rotateKey() {
    if (!canRotateKeys || !window.confirm('确认轮换签名密钥吗？\n轮换后新密钥立即用于签发；旧公钥会在 KEY_ROTATION_GRACE_SECONDS 配置的保留窗口内继续用于验签（该窗口需覆盖 Access Token 和 ID Token 有效期），过期的旧密钥材料将在后续启动或轮换时清理。')) return
    setBusy(true)
    try {
      setKeyResult(await apiFetch<KeyRotationResponse>('/api/v1/admin/keys/rotate', { method: 'POST' }))
      flash('签名密钥已轮换。')
    } catch (reason) {
      flash(reason instanceof Error ? reason.message : '签名密钥轮换失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex flex-col gap-6">
      {message ? <Notice tone={message.tone}>{message.text}</Notice> : null}
      <PasskeyPanel onMessage={flash} onDirtyChange={reportPasskeyDirty} />
      <EmailPolicyPanel onMessage={flash} onDirtyChange={reportEmailPolicyDirty} />
      <SmtpPanel onMessage={flash} onDirtyChange={reportSmtpDirty} />
      <SecurityLimitsPanel onMessage={flash} onDirtyChange={reportSecurityLimitsDirty} />
      <SessionLifetimePanel onMessage={flash} onDirtyChange={reportSessionLifetimeDirty} />
      {canManageProviders ? (
        <OAuthProvidersPanel onMessage={flash} onDirtyChange={reportOAuthDirty} />
      ) : (
        <HudPanel>
          <h2 className="chenxing-h2 flex items-center gap-2">
            <Icon name="link" className="text-[var(--chenxing-cyan)]" size={18} />
            自定义 OAuth 提供商
          </h2>
          <p className="chenxing-caption mt-1.5">需要 `manage_identity_providers` 权限后才能管理外部身份提供商。</p>
        </HudPanel>
      )}
      {canManageIssuer ? <IssuerPanel onMessage={flash} onDirtyChange={reportIssuerDirty} /> : null}
      <RegistrationPanel onMessage={flash} onDirtyChange={reportRegistrationDirty} />
      <HudPanel>
        <h2 className="chenxing-h2 flex items-center gap-2">
          <Icon name="key-round" className="text-[var(--chenxing-cyan)]" size={18} />
          签名密钥
        </h2>
        <p className="chenxing-caption mt-1.5">响应只返回 kid 和已发布公钥数量，不包含私钥材料。</p>
        {keyResult ? (
          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <div className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
              <p className="chenxing-label mb-1">当前 key_id</p>
              <p className="chenxing-mono text-sm text-[var(--chenxing-ice)]">{keyResult.key_id}</p>
            </div>
            <div className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
              <p className="chenxing-label mb-1">已发布公钥数量</p>
              <p className="chenxing-display text-2xl">{keyResult.published_key_count}</p>
            </div>
          </div>
        ) : null}
        <div className="mt-5">
          <Button variant="danger" icon="refresh-cw" disabled={!canRotateKeys || busy} onClick={() => void rotateKey()}>
            {canRotateKeys ? '轮换签名密钥' : '缺少 rotate_keys 权限'}
          </Button>
        </div>
      </HudPanel>
    </div>
  )
}
