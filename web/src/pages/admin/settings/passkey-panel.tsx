import { useState, type FormEvent } from 'react'
import {
  apiFetch,
  type PasskeyAuthenticatorAttachment,
  type PasskeySetting,
  type PasskeyUserVerification,
} from '../../../api'
import { Button, Field, HudPanel, Icon, Notice, ToggleRow } from '../../../components/ui'
import { SelectField } from '../../../components/select'
import { settingsEqual, useDirtyReport, useSettingsResource, type SettingsPanelProps } from './panel'

function splitOrigins(value: string): string[] {
  return value.replace(/,/g, ' ').split(/\s+/).map((item) => item.trim()).filter(Boolean)
}

/** 与服务端 `is_loopback_host`（src/settings/domain.rs）同规则：http 回环例外。 */
function isLoopbackHost(url: URL): boolean {
  const host = url.hostname
  if (host === 'localhost') return true
  const ipv6 = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : null
  if (ipv6 === '::1') return true
  if (ipv6 !== null) return false
  if (!host.startsWith('127.')) return false
  return host.split('.').every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)
}

export type PasskeyOriginsValidation = { origins: string[] } | { error: string }

const MAX_ALLOWED_ORIGINS = 32

/**
 * Origin 白名单的前端校验，规则与服务端 `PasskeySetting::validate` +
 * `normalize_origins`（src/settings/domain.rs）保持一致：
 * - 非空，最多 32 个；
 * - 每个必须是 `scheme://host[:port]` 形式的完整 Origin，不带路径、查询、片段或用户信息；
 * - 协议仅 https；http 只在开启「允许不安全的 Origin」或 host 是回环地址时放行；
 * - host（小写）必须等于 RP ID 或是它的子域。
 * 提交前拦截，避免只能靠后端 400 的笼统报错定位是哪个 Origin 不合法。
 */
export function validatePasskeyOrigins(
  text: string,
  rpId: string,
  allowInsecure: boolean,
): PasskeyOriginsValidation {
  const origins = splitOrigins(text)
  const hasDuplicateInput = new Set(origins.map((origin) => origin.toLowerCase())).size !== origins.length
  if (origins.length === 0) return { error: '请至少填写一个 Origin。' }
  const rp = rpId.trim().toLowerCase()
  if (!rp) return { error: '请先填写 RP ID：Origin 的 host 必须等于 RP ID 或是它的子域。' }
  const normalized: string[] = []
  for (const origin of origins) {
    const message = (reason: string) => `「${origin}」${reason}`
    let url: URL
    try {
      url = new URL(origin)
    } catch {
      return { error: message('不是合法的 URL，请填写完整 Origin，例如 https://auth.clya.top。') }
    }
    // `javascript:`、`data:` 等无 host 的 scheme 会解析成功，必须显式要求 host。
    if (!url.hostname || url.pathname !== '/' || url.search !== '' || url.hash !== '') {
      return { error: message('只能是 scheme://host[:port] 形式的 Origin，不能带路径、查询参数或片段。') }
    }
    if (url.username || url.password) {
      return { error: message('不能包含用户名或密码。') }
    }
    const schemeOk = url.protocol === 'https:'
      || (url.protocol === 'http:' && (allowInsecure || isLoopbackHost(url)))
    if (!schemeOk) {
      return {
        error: message(allowInsecure
          ? '的协议不受支持，仅允许 https 或 http。'
          : '必须使用 https；http 仅允许 localhost 等本机地址，或开启「允许不安全的 Origin」。'),
      }
    }
    const host = url.hostname.toLowerCase()
    if (!(host === rp || host.endsWith(`.${rp}`))) {
      return { error: message(`的 host 必须等于 RP ID（${rp}）或是它的子域。`) }
    }
    const scheme = origin.match(/^([^:]+):\/\//)?.[1] ?? url.protocol.slice(0, -1)
    const authority = origin.slice(scheme.length + 3).split(/[/?#]/, 1)[0]
    const inputHost = url.port ? authority.slice(0, -(url.port.length + 1)) : authority
    const value = hasDuplicateInput
      ? `${url.protocol}//${host}${url.port ? `:${url.port}` : ''}`
      : `${scheme}://${inputHost}${url.port ? `:${url.port}` : ''}`
    const key = `${url.protocol}//${host}${url.port ? `:${url.port}` : ''}`
    if (!normalized.some((item) => item.toLowerCase() === key)) {
      normalized.push(value)
      if (normalized.length > MAX_ALLOWED_ORIGINS) {
        return { error: `Origin 数量不能超过 ${MAX_ALLOWED_ORIGINS} 个。` }
      }
    }
  }
  return { origins: normalized }
}

export function PasskeyPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [setting, setSetting] = useState<PasskeySetting | null>(null)
  /* 上次成功加载/保存的基线：当前编辑与它不一致即视为有未保存草稿（#381）。 */
  const [savedSetting, setSavedSetting] = useState<PasskeySetting | null>(null)
  const [originsText, setOriginsText] = useState('')
  const [originsError, setOriginsError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const { loading } = useSettingsResource<PasskeySetting>({
    path: '/api/v1/admin/settings/passkey',
    onMessage,
    failureMessage: 'Passkey 设置加载失败。',
    apply: (value) => {
      setSetting(value)
      setSavedSetting(value)
      setOriginsText(value.allowed_origins.join(', '))
      setOriginsError(null)
    },
  })

  const dirty = Boolean(savedSetting && (
    !settingsEqual(setting, savedSetting) || originsText !== savedSetting.allowed_origins.join(', ')
  ))
  useDirtyReport(dirty, onDirtyChange)

  function updateSetting(patch: Partial<PasskeySetting>) {
    if (busy) return
    setSetting((current) => current ? { ...current, ...patch } : current)
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !setting) return
    const validation = validatePasskeyOrigins(originsText, setting.rp_id, setting.allow_insecure_origin)
    if ('error' in validation) {
      setOriginsError(validation.error)
      onMessage(validation.error, 'warning')
      return
    }
    setBusy(true)
    try {
      const payload: PasskeySetting = {
        ...setting,
        allowed_origins: validation.origins,
      }
      const value = await apiFetch<PasskeySetting>('/api/v1/admin/settings/passkey', {
        method: 'PUT',
        body: JSON.stringify(payload),
      })
      setSetting(value)
      setSavedSetting(value)
      setOriginsText(value.allowed_origins.join(', '))
      setOriginsError(null)
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
              onChange={(event) => {
                if (!busy) {
                  setOriginsText(event.target.value)
                  setOriginsError(null)
                }
              }}
              placeholder="https://auth.clya.top, https://app.clya.top"
              hint="多个 Origin 用逗号或空格分隔。host 必须等于 RP ID 或是它的子域，仅 https（http 仅限本机地址或开启「允许不安全的 Origin」）。"
              errorText={originsError ?? undefined}
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
