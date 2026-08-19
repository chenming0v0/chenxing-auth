import { useEffect, useState, type FormEvent } from 'react'
import { ApiError, apiFetch, type IssuerSettingResponse, type RegistrationSetting } from '../../../api'
import { Button, HudPanel, Icon, Notice, ToggleRow } from '../../../components/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, type SettingsPanelProps } from './panel'

/**
 * Issuer 闸门文案：面板常驻警告、拨动拦截提示与保存被 503 拒绝时共用同一句。
 *
 * 刻意只在本面板内映射 `issuer_not_configured`，不进 api.ts 的全局错误码表：
 * 同一个错误码还来自公开注册、登录和管理建号（src/error.rs:244 的五处调用），
 * 那些场景的调用者是访客，看到「无法开启」这种管理端开关口径只会被误导。
 */
export const ISSUER_GATE_MESSAGE = '未能配置OIDC Issuer无法开启'

export function RegistrationPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [setting, setSetting] = useState<RegistrationSetting | null>(null)
  /* 上次成功加载/保存的基线：当前编辑与它不一致即视为有未保存草稿（#381）。 */
  const [savedSetting, setSavedSetting] = useState<RegistrationSetting | null>(null)
  const [busy, setBusy] = useState(false)
  /* Issuer 闸门：公开注册依赖运行时有效的 OIDC Issuer，未配置时保存会被后端
     以 503 issuer_not_configured 拒绝。复用 IssuerPanel 的同一端点与响应形状
     推导就绪状态，在前端先行拦截。null = 尚未取回，此时不拦截、由后端兜底。 */
  const [issuerReady, setIssuerReady] = useState<boolean | null>(null)

  const { loading } = useSettingsResource<RegistrationSetting>({
    path: '/api/v1/admin/settings/registration',
    onMessage,
    failureMessage: '公开注册设置加载失败。',
    apply: (value) => {
      setSetting(value)
      setSavedSetting(value)
    },
  })

  useEffect(() => {
    let active = true
    apiFetch<IssuerSettingResponse>('/api/v1/admin/settings/issuer')
      .then((value) => { if (active) setIssuerReady(value.phase === 'issuer_loaded') })
      .catch(() => { if (active) setIssuerReady(false) })
    return () => { active = false }
  }, [])

  const dirty = Boolean(savedSetting && !settingsEqual(setting, savedSetting))
  useDirtyReport(dirty, onDirtyChange)

  function updateSetting(patch: Partial<RegistrationSetting>) {
    if (busy) return
    if (patch.enabled === true && issuerReady === false) {
      onMessage(ISSUER_GATE_MESSAGE, 'warning')
      return
    }
    setSetting((current) => current ? { ...current, ...patch } : current)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !setting) return
    setBusy(true)
    try {
      const value = await apiFetch<RegistrationSetting>('/api/v1/admin/settings/registration', {
        method: 'PUT',
        body: JSON.stringify(setting),
      })
      setSetting(value)
      setSavedSetting(value)
      onMessage('公开注册设置已保存。')
    } catch (reason) {
      // 后端是权威闸门：前端拦截被绕过或 Issuer 在编辑期间失效时，503 会走到这里。
      const message = reason instanceof ApiError && reason.code === 'issuer_not_configured'
        ? ISSUER_GATE_MESSAGE
        : reason instanceof Error ? reason.message : '公开注册设置保存失败。'
      onMessage(message, 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="chenxing-h2 flex items-center gap-2">
            <Icon name="user-plus" className="text-[var(--chenxing-cyan)]" size={18} />
            公开注册
          </h2>
          <p className="chenxing-caption mt-1.5">控制访客能否在登录页自助创建辰星通行证账号。</p>
        </div>
      </div>
      {issuerReady === false ? (
        <div className="mt-5"><Notice tone="warning">{ISSUER_GATE_MESSAGE}</Notice></div>
      ) : null}
      {loading || !setting ? (
        <div className="mt-5"><Notice>正在加载公开注册设置。</Notice></div>
      ) : (
        <form className="mt-5 flex flex-col gap-4" onSubmit={save}>
          <fieldset disabled={busy} className="contents">
            <ToggleRow
              title="开启公开注册"
              description="允许访客自助创建账号；关闭时新账号只能由管理员创建"
              checked={setting.enabled}
              disabled={busy}
              onChange={(enabled) => updateSetting({ enabled })}
            />
            <ToggleRow
              title="要求邮箱所有权验证"
              description="开启后注册者必须完成邮箱所有权验证；验证投递能力在建，开启期间公开注册暂不可用。"
              checked={setting.email_verification_required}
              disabled={busy}
              onChange={(email_verification_required) => updateSetting({ email_verification_required })}
            />
            <ToggleRow
              title="注册要求邀请码"
              description="开启后注册者必须提供有效邀请码；可与邮箱域名白名单和邮箱验证叠加。"
              checked={setting.invitation_code_required}
              disabled={busy}
              onChange={(invitation_code_required) => updateSetting({ invitation_code_required })}
            />
            <div>
              <Button type="submit" icon="save" disabled={busy}>保存公开注册设置</Button>
            </div>
          </fieldset>
        </form>
      )}
    </HudPanel>
  )
}
