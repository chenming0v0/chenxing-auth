import { useState, type FormEvent } from 'react'
import { apiFetch, type SmtpSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice, PasswordField, ToggleRow } from '../../../components/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, validateIntegerWithinRange, type SettingsPanelProps } from './panel'

/** 草稿里的端口以字符串保存：清空输入框时必须保留空串，而不是回填 0（#376）。 */
type SmtpDraft = Omit<SmtpSetting, 'port'> & { port: string }

function toDraft(value: SmtpSetting): SmtpDraft {
  return { ...value, port: String(value.port) }
}

/**
 * 端口必须是 1-65535 的整数（u16，与后端 `SmtpSetting.port` 一致）。
 * 非法输入在保存前拦截并给出明确文案，绝不把 0 或越界值发给后端。
 */
export function validateSmtpPort(rawValue: string): { value: number } | { error: string } {
  return validateIntegerWithinRange(rawValue, 'SMTP 端口', 65535)
}

export function SmtpPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [draft, setDraft] = useState<SmtpDraft | null>(null)
  /* 上次成功加载/保存的基线：当前编辑与它不一致即视为有未保存草稿（#381）。 */
  const [savedDraft, setSavedDraft] = useState<SmtpDraft | null>(null)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)

  const { loading } = useSettingsResource<SmtpSetting>({
    path: '/api/v1/admin/settings/smtp',
    onMessage,
    failureMessage: 'SMTP 设置加载失败。',
    apply: (value) => {
      const next = toDraft(value)
      setDraft(next)
      setSavedDraft(next)
    },
  })

  const dirty = Boolean(savedDraft && (password !== '' || !settingsEqual(draft, savedDraft)))
  useDirtyReport(dirty, onDirtyChange)

  function updateDraft(patch: Partial<SmtpDraft>) {
    if (busy) return
    setDraft((current) => current ? { ...current, ...patch } : current)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !draft) return
    const port = validateSmtpPort(draft.port)
    if ('error' in port) {
      onMessage(port.error, 'warning')
      return
    }
    setBusy(true)
    try {
      const value = await apiFetch<SmtpSetting>('/api/v1/admin/settings/smtp', {
        method: 'PUT',
        body: JSON.stringify({
          host: draft.host,
          port: port.value,
          username: draft.username,
          from_address: draft.from_address,
          ssl_enabled: draft.ssl_enabled,
          force_auth_login: draft.force_auth_login,
          password: password || null,
        }),
      })
      const next = toDraft(value)
      setDraft(next)
      setSavedDraft(next)
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
      {loading || !draft ? (
        <div className="mt-5"><Notice>正在加载 SMTP 设置。</Notice></div>
      ) : (
        <form className="mt-5" noValidate onSubmit={save}>
          <fieldset disabled={busy} className="flex min-w-0 flex-col gap-4 border-0 p-0">
            <div className="grid gap-4 sm:grid-cols-3">
              <Field label="SMTP 服务器地址" value={draft.host} onChange={(event) => updateDraft({ host: event.target.value })} placeholder="smtp.example.com" />
              <Field
                label="SMTP 端口"
                type="number"
                inputMode="numeric"
                min="1"
                max="65535"
                step="1"
                value={draft.port}
                onChange={(event) => updateDraft({ port: event.target.value })}
                hint="端口范围 1 到 65535"
              />
              <Field label="SMTP 账户" value={draft.username} onChange={(event) => updateDraft({ username: event.target.value })} placeholder="noreply@auth.clya.top" />
              <Field label="SMTP 发送者邮箱" value={draft.from_address} onChange={(event) => updateDraft({ from_address: event.target.value })} placeholder="辰星认证中枢 <noreply@auth.clya.top>" />
              <div className="sm:col-span-2">
                <PasswordField
                  label="SMTP 访问凭证"
                  value={password}
                  onChange={(event) => { if (!busy) setPassword(event.target.value) }}
                  placeholder={draft.password_configured ? '已配置，留空则保持不变' : '敏感信息不会回显到前端'}
                  hint={draft.password_configured ? '当前已配置访问凭证，留空可保留原值。' : '保存后不会回显明文。'}
                />
              </div>
            </div>
            <ToggleRow
              title="启用 SMTP SSL"
              description="通过 TLS 加密连接投递邮件"
              checked={draft.ssl_enabled}
              disabled={busy}
              onChange={(ssl_enabled) => updateDraft({ ssl_enabled })}
            />
            <ToggleRow
              title="强制使用 AUTH LOGIN"
              description="部分服务商要求 AUTH LOGIN 认证方式"
              checked={draft.force_auth_login}
              disabled={busy}
              onChange={(force_auth_login) => updateDraft({ force_auth_login })}
            />
            <div>
              <Button type="submit" icon="save" disabled={busy}>保存 SMTP 设置</Button>
            </div>
          </fieldset>
        </form>
      )}
    </HudPanel>
  )
}
