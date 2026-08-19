import type { FormEvent, ReactNode } from 'react'
import type { SecurityTotpStart } from '../../api'
import { Badge, Button, Icon } from '../../components/ui'
import { TotpEnrollmentDialog } from './totp-enrollment-dialog'

type SecuritySettingsProps = {
  loading: boolean
  busy: string | null
  totpEnabled: boolean
  passkeyCount: number
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
  loading,
  busy,
  totpEnabled,
  passkeyCount,
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
  const protectedAccount = totpEnabled || passkeyCount > 0

  return (
    <div aria-labelledby="security-settings-heading">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 id="security-settings-heading" className="chenxing-h3">登录与身份验证</h3>
          <p className="chenxing-caption mt-1 max-w-2xl">管理密码、设备凭据和动态验证码。敏感操作会要求重新确认当前密码。</p>
        </div>
        <Badge tone={protectedAccount ? 'success' : 'neutral'}>{loading ? '读取中' : protectedAccount ? '多重保护' : '仅密码'}</Badge>
      </div>

      {!loading && !protectedAccount ? (
        <div className="mb-4 flex items-start gap-3 rounded-[var(--chenxing-radius-md)] border border-[rgba(245,199,106,0.28)] bg-[rgba(245,199,106,0.06)] px-4 py-3">
          <Icon name="shield-alert" size={18} className="mt-0.5 shrink-0 text-[var(--chenxing-gold)]" />
          <div>
            <p className="chenxing-body text-sm font-semibold">当前使用密码登录</p>
            <p className="chenxing-caption mt-1">没有启用额外验证方式时，密码验证成功会直接建立普通会话。</p>
          </div>
        </div>
      ) : null}

      <div className="space-y-3">
        <SecurityActionRow
          icon="user"
          title="账户资料"
          description={profileSummary}
          status={<Badge>2 项资料</Badge>}
          actions={profileAction}
        />

        <SecurityActionRow
          icon="mail"
          title="邮箱地址"
          description={`当前邮箱：${userEmail}`}
          status={<Badge tone="success">已验证</Badge>}
          actions={emailAction}
        />

        <SecurityActionRow
          icon="lock-keyhole"
          title="密码管理"
          description="定期更新密码；修改成功后所有现有会话都会被撤销。"
          status={<Badge tone="success">已设置</Badge>}
          actions={passwordAction}
        />

        <SecurityActionRow
          icon="key-round"
          accent="gold"
          title="Passkey 登录"
          description="使用设备生物识别或安全密钥完成无密码验证，可同时保留多个设备凭据。"
          status={<Badge tone={passkeyCount > 0 ? 'success' : 'neutral'}>{loading ? '读取中' : passkeyCount > 0 ? `${passkeyCount} 个凭据` : '未启用'}</Badge>}
          actions={(
            <>
              <Button className="min-h-11" icon="key-round" disabled={busy !== null || loading} onClick={onStartPasskey}>
                {busy === 'passkey' ? '等待设备确认…' : passkeyCount > 0 ? '添加 Passkey' : '注册 Passkey'}
              </Button>
              {passkeyCount > 0 ? (
                <Button className="min-h-11" variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => onRemove('passkey')}>
                  移除全部
                </Button>
              ) : null}
            </>
          )}
        />

        <SecurityActionRow
          icon="shield-check"
          title="验证器应用"
          description="扫描二维码绑定 TOTP 动态验证码，为密码登录增加独立的第二步验证。"
          status={<Badge tone={totpEnabled ? 'success' : 'neutral'}>{loading ? '读取中' : totpEnabled ? '已启用' : '未启用'}</Badge>}
          actions={totpEnabled ? (
            <Button className="min-h-11" variant="danger" icon="trash-2" disabled={busy !== null} onClick={() => onRemove('totp')}>
              移除验证器
            </Button>
          ) : (
            <Button className="min-h-11" icon="plus" disabled={busy !== null || loading} onClick={onStartTotp}>
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

function SecurityActionRow({ icon, accent = 'cyan', title, description, status, actions }: {
  icon: string
  accent?: 'cyan' | 'gold'
  title: string
  description: string
  status: ReactNode
  actions?: ReactNode
}) {
  const accentClass = accent === 'gold' ? 'text-[var(--chenxing-gold)]' : 'text-[var(--chenxing-cyan)]'
  return (
    <section className="rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.38)] p-4 transition-colors duration-200 hover:border-[var(--chenxing-border-strong)] sm:p-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-start gap-3.5">
          <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[var(--chenxing-muted)] ${accentClass}`}>
            <Icon name={icon} size={19} />
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h4 className="chenxing-body text-sm font-semibold">{title}</h4>
              {status}
            </div>
            <p className="chenxing-caption mt-1 max-w-2xl">{description}</p>
          </div>
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2 lg:justify-end">{actions}</div> : null}
      </div>
    </section>
  )
}
