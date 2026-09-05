import type { FormEvent, ReactNode } from 'react'
import type { SecurityFactorSummary, SecurityTotpStart } from '../../api'
import { Badge, Button, Icon, SettingsActionRow } from '@chenxing/ui'
import { TotpEnrollmentDialog } from './totp-enrollment-dialog'

export type SecurityFactorState =
  | { status: 'loading' }
  | { status: 'failed' }
  | { status: 'ready'; summary: SecurityFactorSummary }

type SecuritySettingsProps = {
  factors: SecurityFactorState
  busy: string | null
  totpData: SecurityTotpStart | null
  code: string
  onCode: (value: string) => void
  onStartTotp: () => void
  onCancelTotp: () => void
  onConfirmTotp: (event: FormEvent) => void
  onStartPasskey: () => void
  onRemove: (method: 'totp' | 'passkey') => void
  profileSummary: string
  profileAction: ReactNode
  userEmail: string
  emailAction: ReactNode
  passwordAction: ReactNode
}

export function SecuritySettings({
  factors,
  busy,
  totpData,
  code,
  onCode,
  onStartTotp,
  onCancelTotp,
  onConfirmTotp,
  onStartPasskey,
  onRemove,
  profileSummary,
  profileAction,
  userEmail,
  emailAction,
  passwordAction,
}: SecuritySettingsProps) {
  const summary = factors.status === 'ready' ? factors.summary : null
  const loading = factors.status === 'loading'
  const failed = factors.status === 'failed'
  const totpEnabled = summary?.totp_enabled ?? false
  const passkeyCount = summary?.passkey_count ?? 0
  const protectedAccount = summary !== null && (totpEnabled || passkeyCount > 0)

  return (
    <div aria-labelledby="security-settings-heading">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="security-settings-heading" className="chenxing-h3">登录与身份验证</h3>
          <p className="chenxing-caption mt-1 max-w-2xl">管理密码、设备凭据和动态验证码。敏感操作会要求重新确认当前密码。</p>
        </div>
        <Badge tone={failed ? 'warning' : protectedAccount ? 'success' : 'neutral'}>{loading ? '读取中' : failed ? '状态未知' : protectedAccount ? '多重保护' : '仅密码'}</Badge>
      </div>

      {summary && !protectedAccount ? (
        <div className="mb-4 flex items-start gap-3 rounded-[var(--chenxing-radius-md)] border border-[rgba(245,199,106,0.28)] bg-[rgba(245,199,106,0.06)] px-4 py-3">
          <Icon name="shield-alert" size={18} className="mt-0.5 shrink-0 text-[var(--chenxing-gold)]" />
          <div>
            <p className="chenxing-body text-sm font-semibold">当前使用密码登录</p>
            <p className="chenxing-caption mt-1">没有启用额外验证方式时，密码验证成功会直接建立普通会话。</p>
          </div>
        </div>
      ) : null}

      <div className="space-y-3">
        <SettingsActionRow
          icon="user"
          title="账户资料"
          description={profileSummary}
          status={<Badge>2 项资料</Badge>}
          actions={profileAction}
        />

        <SettingsActionRow
          icon="mail"
          title="邮箱地址"
          description={`当前邮箱：${userEmail}`}
          status={<Badge tone="success">已验证</Badge>}
          actions={emailAction}
        />

        <SettingsActionRow
          icon="lock-keyhole"
          title="密码管理"
          description="定期更新密码；修改成功后所有现有会话都会被撤销。"
          status={<Badge tone="success">已设置</Badge>}
          actions={passwordAction}
        />

        <SettingsActionRow
          icon="key-round"
          accent="gold"
          title="Passkey 登录"
          description="使用设备生物识别或安全密钥完成无密码验证，可同时保留多个设备凭据。"
          status={<Badge tone={failed ? 'warning' : passkeyCount > 0 ? 'success' : 'neutral'}>{loading ? '读取中' : failed ? '状态未知' : passkeyCount > 0 ? `${passkeyCount} 个凭据` : '未启用'}</Badge>}
          actions={summary ? (
            <>
              <Button className="min-h-11" icon="key-round" disabled={busy !== null} onClick={onStartPasskey}>
                {busy === 'passkey' ? '等待设备确认…' : passkeyCount > 0 ? '添加 Passkey' : '注册 Passkey'}
              </Button>
              {passkeyCount > 0 ? (
                <Button className="min-h-11" variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => onRemove('passkey')}>
                  移除全部
                </Button>
              ) : null}
            </>
          ) : undefined}
        />

        <SettingsActionRow
          icon="shield-check"
          title="验证器应用"
          description="扫描二维码绑定 TOTP 动态验证码，为密码登录增加独立的第二步验证。"
          status={<Badge tone={failed ? 'warning' : totpEnabled ? 'success' : 'neutral'}>{loading ? '读取中' : failed ? '状态未知' : totpEnabled ? '已启用' : '未启用'}</Badge>}
          actions={!summary ? undefined : totpEnabled ? (
            <Button className="min-h-11" variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => onRemove('totp')}>
              移除验证器
            </Button>
          ) : (
            <Button className="min-h-11" icon="plus" disabled={busy !== null} onClick={onStartTotp}>
              {busy === 'totp-start' ? '准备中…' : '绑定验证器'}
            </Button>
          )}
        />
      </div>

      {totpData ? (
        <TotpEnrollmentDialog
          data={totpData}
          code={code}
          busy={busy !== null}
          confirming={busy === 'totp-confirm'}
          onCode={onCode}
          onCancel={onCancelTotp}
          onConfirm={onConfirmTotp}
        />
      ) : null}
    </div>
  )
}
