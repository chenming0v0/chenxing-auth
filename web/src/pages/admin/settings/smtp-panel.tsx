import { useEffect, useState, type FormEvent } from 'react'
import { apiFetch, type SmtpSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice, PasswordField, ToggleRow } from '../../../components/ui'

export function SmtpPanel({ onMessage }: { onMessage: (message: string, tone?: 'success' | 'warning') => void }) {
  const [setting, setSetting] = useState<SmtpSetting | null>(null)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    void apiFetch<SmtpSetting>('/api/v1/admin/settings/smtp')
      .then((value) => { if (active) setSetting(value) })
      .catch((reason: unknown) => onMessage(reason instanceof Error ? reason.message : 'SMTP 设置加载失败。', 'warning'))
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [onMessage])

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!setting) return
    setBusy(true)
    try {
      const value = await apiFetch<SmtpSetting>('/api/v1/admin/settings/smtp', {
        method: 'PUT',
        body: JSON.stringify({
          host: setting.host,
          port: Number(setting.port) || 0,
          username: setting.username,
          from_address: setting.from_address,
          ssl_enabled: setting.ssl_enabled,
          force_auth_login: setting.force_auth_login,
          password: password || null,
        }),
      })
      setSetting(value)
      setPassword('')
      onMessage('SMTP 设置已保存。')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : 'SMTP 设置保存失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <h2 className="chenxing-h2 flex items-center gap-2">
        <Icon name="send" className="text-[var(--chenxing-cyan)]" size={18} />
        配置 SMTP
      </h2>
      <p className="chenxing-caption mt-1.5">用以支持系统的邮件发送</p>
      {loading || !setting ? (
        <div className="mt-5"><Notice>正在加载 SMTP 设置。</Notice></div>
      ) : (
        <form className="mt-5 flex flex-col gap-4" onSubmit={save}>
          <div className="grid gap-4 sm:grid-cols-3">
            <Field label="SMTP 服务器地址" value={setting.host} onChange={(event) => setSetting({ ...setting, host: event.target.value })} placeholder="smtp.example.com" />
            <Field label="SMTP 端口" type="number" value={String(setting.port)} onChange={(event) => setSetting({ ...setting, port: Number(event.target.value) || 0 })} />
            <Field label="SMTP 账户" value={setting.username} onChange={(event) => setSetting({ ...setting, username: event.target.value })} placeholder="noreply@auth.clya.top" />
            <Field label="SMTP 发送者邮箱" value={setting.from_address} onChange={(event) => setSetting({ ...setting, from_address: event.target.value })} placeholder="辰星认证中枢 <noreply@auth.clya.top>" />
            <div className="sm:col-span-2">
              <PasswordField
                label="SMTP 访问凭证"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder={setting.password_configured ? '已配置，留空则保持不变' : '敏感信息不会回显到前端'}
                hint={setting.password_configured ? '当前已配置访问凭证，留空可保留原值。' : '保存后不会回显明文。'}
              />
            </div>
          </div>
          <ToggleRow
            title="启用 SMTP SSL"
            description="通过 TLS 加密连接投递邮件"
            checked={setting.ssl_enabled}
            onChange={(ssl_enabled) => setSetting({ ...setting, ssl_enabled })}
          />
          <ToggleRow
            title="强制使用 AUTH LOGIN"
            description="部分服务商要求 AUTH LOGIN 认证方式"
            checked={setting.force_auth_login}
            onChange={(force_auth_login) => setSetting({ ...setting, force_auth_login })}
          />
          <div>
            <Button type="submit" icon="save" disabled={busy}>保存 SMTP 设置</Button>
          </div>
        </form>
      )}
    </HudPanel>
  )
}
