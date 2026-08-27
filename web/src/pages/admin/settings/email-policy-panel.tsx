import { useState, type FormEvent, type KeyboardEvent } from 'react'
import { ApiError, apiFetch, type EmailPolicySetting, type UpdateEmailPolicySetting } from '../../../api'
import { Button, Chip, Field, HudPanel, Icon, Notice, ToggleRow } from '@chenxing/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, type SettingsPanelProps } from './panel'

const MAX_ALLOWED_DOMAINS = 128
const MAX_DOMAIN_LENGTH = 253

function normalizeDomain(value: string): string {
  return value.trim().replace(/[A-Z]/g, (character) => character.toLowerCase())
}

function domainValidationError(value: string): string {
  const domain = normalizeDomain(value)
  if (!domain) return ''
  if (domain.length > MAX_DOMAIN_LENGTH) return '域名不能超过 253 个字符。'
  if (domain.startsWith('.') || domain.endsWith('.') || domain.includes('..')) {
    return '域名不能以点开头或结尾，也不能包含连续点号。'
  }
  if (domain.includes('@')) return '这里只填写域名，例如 example.com，不要填写邮箱地址。'
  if (!domain.includes('.')) return '请输入包含点号的完整域名，例如 example.com。'
  if (!/^[a-z0-9.-]+$/.test(domain)) return '域名只能包含 ASCII 字母、数字、连字符和点号。'
  return ''
}

function hasDomain(domains: string[], domain: string): boolean {
  return domains.some((item) => normalizeDomain(item) === domain)
}

function hasConfiguredDomain(domains: string[]): boolean {
  return domains.some((domain) => Boolean(normalizeDomain(domain)))
}

export function EmailPolicyPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [setting, setSetting] = useState<EmailPolicySetting | null>(null)
  const [savedSetting, setSavedSetting] = useState<EmailPolicySetting | null>(null)
  const [draftDomain, setDraftDomain] = useState('')
  const [domainError, setDomainError] = useState('')
  const [busy, setBusy] = useState(false)

  const { loading } = useSettingsResource<EmailPolicySetting>({
    path: '/api/v1/admin/settings/email-policy',
    onMessage,
    failureMessage: '邮箱域名白名单加载失败。',
    apply: (value) => {
      setSetting(value)
      setSavedSetting(value)
    },
  })

  /* 编辑与基线不一致、或输入框里还躺着未添加的域名，都算未保存草稿（#381）。 */
  const dirty = Boolean(savedSetting && (!settingsEqual(setting, savedSetting) || draftDomain !== ''))
  useDirtyReport(dirty, onDirtyChange)

  function addDomain() {
    if (busy || !setting) return
    const domain = normalizeDomain(draftDomain)
    const error = domainValidationError(draftDomain)
    if (error) {
      setDomainError(error)
      return
    }
    if (!domain) {
      setDomainError('')
      return
    }
    if (hasDomain(setting.allowed_domains, domain)) {
      setDraftDomain('')
      setDomainError('')
      return
    }
    if (setting.allowed_domains.length >= MAX_ALLOWED_DOMAINS) {
      setDomainError('最多添加 128 个允许域名。')
      return
    }
    setSetting({ ...setting, allowed_domains: [...setting.allowed_domains, domain] })
    setDraftDomain('')
    setDomainError('')
  }

  function onDomainKey(event: KeyboardEvent<HTMLInputElement>) {
    if (busy) return
    if (event.key === 'Enter') {
      event.preventDefault()
      addDomain()
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !setting) return
    const pendingDomainError = domainValidationError(draftDomain)
    if (pendingDomainError) {
      setDomainError(pendingDomainError)
      return
    }
    if (setting.whitelist_enabled && !hasConfiguredDomain(setting.allowed_domains)) {
      onMessage('白名单已启用但允许域名列表为空，无法保存。请至少添加一个域名，或关闭白名单。', 'warning')
      return
    }
    const broadensActiveAllowlist = Boolean(
      savedSetting?.whitelist_enabled
      && hasConfiguredDomain(savedSetting.allowed_domains)
      && !setting.whitelist_enabled
    )
    if (
      broadensActiveAllowlist
      && !window.confirm(
        `确认关闭邮箱域名白名单吗？\n关闭后，注册不再按允许域名限制，当前允许域名列表将被忽略；${setting.alias_restriction_enabled
          ? '当前启用的别名限制仍会拒绝含 + 的邮箱地址。'
          : '当前未启用别名限制。'}`,
      )
    ) return
    const needsRepairConfirmation = Boolean(savedSetting?.repair_required)
    if (needsRepairConfirmation && !window.confirm('服务端检测到已保存的邮箱策略损坏。继续保存会用当前表单明确覆盖损坏值，并恢复新的 fail-closed 策略。确认修复吗？')) return
    setBusy(true)
    try {
      const payload: UpdateEmailPolicySetting = {
        whitelist_enabled: setting.whitelist_enabled,
        alias_restriction_enabled: setting.alias_restriction_enabled,
        allowed_domains: setting.allowed_domains,
        expected_generation: savedSetting?.generation ?? 0,
        confirm_repair: Boolean(savedSetting?.repair_required),
      }
      const value = await apiFetch<EmailPolicySetting>('/api/v1/admin/settings/email-policy', {
        method: 'PUT',
        body: JSON.stringify(payload),
      })
      setSetting(value)
      setSavedSetting(value)
      onMessage('邮箱域名白名单设置已保存。')
      } catch (reason) {
        const message = reason instanceof ApiError && reason.code === 'setting_conflict'
          ? '邮箱域名白名单已被其他管理员修改，请刷新后重新编辑。'
          : reason instanceof Error ? reason.message : '邮箱域名白名单保存失败。'
        onMessage(message, 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <h2 className="chenxing-h2 flex items-center gap-2">
        <Icon name="mail" className="text-[var(--chenxing-cyan)]" size={18} />
        配置邮箱域名白名单
      </h2>
      <p className="chenxing-caption mt-1.5">用以防止恶意用户利用临时邮箱批量注册</p>
      {loading || !setting ? (
        <div className="mt-5"><Notice>正在加载邮箱域名白名单。</Notice></div>
      ) : (
        <form className="mt-5 flex flex-col gap-4" onSubmit={save}>
          <fieldset disabled={busy} className="contents">
            <ToggleRow
              title="启用邮箱域名白名单"
              description="仅允许下列域名的邮箱完成注册"
              checked={setting.whitelist_enabled}
              disabled={busy}
              onChange={(whitelist_enabled) => { if (!busy) setSetting({ ...setting, whitelist_enabled }) }}
            />
            <ToggleRow
              title="启用邮箱别名限制"
              description="禁止 + 号别名规避唯一性"
              checked={setting.alias_restriction_enabled}
              disabled={busy}
              onChange={(alias_restriction_enabled) => { if (!busy) setSetting({ ...setting, alias_restriction_enabled }) }}
            />
          </fieldset>
          {setting.repair_required ? <Notice tone="warning">服务端检测到已保存的邮箱策略损坏（{setting.diagnostic ?? 'unknown'}）。当前表单只是 fail-closed 修复预览；保存前必须确认显式修复。</Notice> : null}
          <Notice>
            {setting.whitelist_enabled
              ? '白名单开启时，只允许与下方列表精确匹配的邮箱域名；列表至少需要一个域名。'
              : '白名单关闭时，允许域名列表（包括空列表）会被忽略，域名不会限制注册。'}{' '}
            {setting.alias_restriction_enabled
              ? '别名限制先于域名判断，含 + 的邮箱地址始终拒绝。'
              : '开启别名限制后，含 + 的邮箱地址会先于域名判断被拒绝。'}
          </Notice>
          {setting.whitelist_enabled && !hasConfiguredDomain(setting.allowed_domains) ? (
            <Notice tone="warning">白名单已启用但允许域名列表为空，无法保存。请至少添加一个域名，或关闭白名单。</Notice>
          ) : null}
          <fieldset disabled={busy} className="contents">
            <div>
              <p className="chenxing-label">已允许的域名</p>
              <div className="mt-2 flex flex-wrap gap-2">
                {setting.allowed_domains.length ? setting.allowed_domains.map((domain) => (
                  <Chip
                    key={domain}
                    onRemove={() => {
                      if (busy) return
                      setSetting((current) => current ? {
                        ...current,
                        allowed_domains: current.allowed_domains.filter((item) => item !== domain),
                      } : current)
                    }}
                  >
                    {domain}
                  </Chip>
                )) : <p className="chenxing-caption">尚未添加域名。</p>}
              </div>
            </div>
            <div className="flex flex-col gap-3 sm:flex-row">
              <div className="flex-1">
                <Field
                  label="输入要添加的邮箱域名"
                  value={draftDomain}
                  onChange={(event) => {
                    if (busy) return
                    const value = event.target.value
                    setDraftDomain(value)
                    if (domainError) setDomainError(domainValidationError(value))
                  }}
                  onKeyDown={onDomainKey}
                  onBlur={() => { if (!busy) setDomainError(domainValidationError(draftDomain)) }}
                  placeholder="例如: gmail.com"
                  maxLength={MAX_DOMAIN_LENGTH}
                  spellCheck={false}
                  errorText={domainError || undefined}
                  hint={domainError ? undefined : '仅接受完整域名，例如 example.com；不含 @、协议、路径或通配符。'}
                />
              </div>
              <div className="flex items-end">
                <Button type="button" icon="plus" onClick={addDomain} disabled={busy}>添加</Button>
              </div>
            </div>
            <div>
              <Button type="submit" variant="ghost" icon="save" disabled={busy}>保存邮箱域名白名单设置</Button>
            </div>
          </fieldset>
        </form>
      )}
    </HudPanel>
  )
}
