import { useState, type FormEvent } from 'react'
import {
  apiFetch,
  type PasskeyAuthenticatorAttachment,
  type PasskeySetting,
  type PasskeyUserVerification,
} from '../../../api'
import { Button, Field, HudPanel, Icon, Notice, ToggleRow } from '../../../components/ui'
import { SelectField } from '../../../components/select'
import { useSettingsResource, type SettingsPanelProps } from './panel'

function splitOrigins(value: string): string[] {
  return value.replace(/,/g, ' ').split(/\s+/).map((item) => item.trim()).filter(Boolean)
}

export function PasskeyPanel({ onMessage }: SettingsPanelProps) {
  const [setting, setSetting] = useState<PasskeySetting | null>(null)
  const [originsText, setOriginsText] = useState('')
  const [busy, setBusy] = useState(false)

  const { loading } = useSettingsResource<PasskeySetting>({
    path: '/api/v1/admin/settings/passkey',
    onMessage,
    failureMessage: 'Passkey 设置加载失败。',
    apply: (value) => {
      setSetting(value)
      setOriginsText(value.allowed_origins.join(', '))
    },
  })

  function updateSetting(patch: Partial<PasskeySetting>) {
    if (busy) return
    setSetting((current) => current ? { ...current, ...patch } : current)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !setting) return
    setBusy(true)
    try {
      const payload: PasskeySetting = {
        ...setting,
        allowed_origins: splitOrigins(originsText),
      }
      const value = await apiFetch<PasskeySetting>('/api/v1/admin/settings/passkey', {
        method: 'PUT',
        body: JSON.stringify(payload),
      })
      setSetting(value)
      setOriginsText(value.allowed_origins.join(', '))
      onMessage('Passkey 设置已保存。')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : 'Passkey 设置保存失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="chenxing-h2 flex items-center gap-2">
            <Icon name="fingerprint" className="text-[var(--chenxing-cyan)]" size={18} />
            配置 Passkey
          </h2>
          <p className="chenxing-caption mt-1.5">用以支持基于 WebAuthn 的无密码登录注册</p>
        </div>
      </div>
      <div className="mt-5 flex items-start gap-3 rounded-[var(--chenxing-radius-md)] border border-[rgba(103,232,249,0.3)] bg-[var(--chenxing-cyan-soft)] px-4 py-3">
        <Icon name="info" size={16} className="mt-0.5 shrink-0 text-[var(--chenxing-cyan)]" />
        <p className="chenxing-caption text-[var(--chenxing-ice)]">
          Passkey 基于设备生物识别或安全密钥实现无密码认证，凭据以公钥形式绑定当前域名（RP ID），私钥永不离开用户设备。启用后用户可在通行证资料中注册 Passkey。
        </p>
      </div>
      {loading || !setting ? (
        <div className="mt-5"><Notice>正在加载 Passkey 设置。</Notice></div>
      ) : (
        <form className="mt-5 flex flex-col gap-4" onSubmit={save}>
          <fieldset disabled={busy} className="contents">
            <ToggleRow
              title="允许通过 Passkey 登录 & 认证"
              description="向所有用户开放 WebAuthn 无密码通道"
              checked={setting.enabled}
              disabled={busy}
              onChange={(enabled) => updateSetting({ enabled })}
            />
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="服务显示名称" value={setting.rp_name} onChange={(event) => updateSetting({ rp_name: event.target.value })} />
              <Field label="网站域名标识 (RP ID)" value={setting.rp_id} onChange={(event) => updateSetting({ rp_id: event.target.value })} placeholder="例如: auth.clya.top" />
              <SelectField
                label="安全验证级别"
                value={setting.user_verification}
                disabled={busy}
                onChange={(value) => updateSetting({ user_verification: value as PasskeyUserVerification })}
                options={[
                  { value: 'preferred', label: '推荐使用（用户可选）' },
                  { value: 'required', label: '必须验证用户身份' },
                  { value: 'discouraged', label: '不要求用户验证' },
                ]}
              />
              <SelectField
                label="设备类型偏好"
                value={setting.authenticator_attachment}
                disabled={busy}
                onChange={(value) => updateSetting({ authenticator_attachment: value as PasskeyAuthenticatorAttachment })}
                options={[
                  { value: 'any', label: '不限制' },
                  { value: 'platform', label: '仅平台认证器' },
                  { value: 'cross_platform', label: '仅跨平台安全密钥' },
                ]}
              />
            </div>
            <ToggleRow
              title="允许不安全的 Origin (HTTP)"
              description="仅用于开发环境，生产环境必须使用 HTTPS"
              checked={setting.allow_insecure_origin}
              disabled={busy}
              onChange={(allow_insecure_origin) => updateSetting({ allow_insecure_origin })}
            />
            <Field
              label="允许的 Origins"
              value={originsText}
              onChange={(event) => { if (!busy) setOriginsText(event.target.value) }}
              placeholder="https://auth.clya.top, https://app.clya.top"
              hint="多个 Origin 可用逗号或空格分隔。"
            />
            <div>
              <Button type="submit" icon="save" disabled={busy}>保存 Passkey 设置</Button>
            </div>
          </fieldset>
        </form>
      )}
    </HudPanel>
  )
}
