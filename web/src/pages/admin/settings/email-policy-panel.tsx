import { useEffect, useState, type FormEvent, type KeyboardEvent } from 'react'
import { apiFetch, type EmailPolicySetting } from '../../../api'
import { Button, Chip, Field, HudPanel, Icon, Notice, ToggleRow } from '../../../components/ui'

export function EmailPolicyPanel({ onMessage }: { onMessage: (message: string, tone?: 'success' | 'warning') => void }) {
  const [setting, setSetting] = useState<EmailPolicySetting | null>(null)
  const [draftDomain, setDraftDomain] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    void apiFetch<EmailPolicySetting>('/api/v1/admin/settings/email-policy')
      .then((value) => { if (active) setSetting(value) })
      .catch((reason: unknown) => onMessage(reason instanceof Error ? reason.message : '邮箱域名白名单加载失败。', 'warning'))
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [onMessage])

  function addDomain() {
    if (!setting) return
    const domain = draftDomain.trim().toLowerCase()
    if (!domain) return
    if (setting.allowed_domains.includes(domain)) {
      setDraftDomain('')
      return
    }
    setSetting({ ...setting, allowed_domains: [...setting.allowed_domains, domain] })
    setDraftDomain('')
  }

  function onDomainKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === 'Enter') {
      event.preventDefault()
      addDomain()
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault()
    if (!setting) return
    setBusy(true)
    try {
      const value = await apiFetch<EmailPolicySetting>('/api/v1/admin/settings/email-policy', {
        method: 'PUT',
        body: JSON.stringify(setting),
      })
      setSetting(value)
      onMessage('邮箱域名白名单设置已保存。')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : '邮箱域名白名单保存失败。', 'warning')
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
          <ToggleRow
            title="启用邮箱域名白名单"
            description="仅允许下列域名的邮箱完成注册"
            checked={setting.whitelist_enabled}
            onChange={(whitelist_enabled) => setSetting({ ...setting, whitelist_enabled })}
          />
          <ToggleRow
            title="启用邮箱别名限制"
            description="禁止 + 号别名规避唯一性"
            checked={setting.alias_restriction_enabled}
            onChange={(alias_restriction_enabled) => setSetting({ ...setting, alias_restriction_enabled })}
          />
          <div>
            <p className="chenxing-label">已允许的域名</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {setting.allowed_domains.length ? setting.allowed_domains.map((domain) => (
                <Chip
                  key={domain}
                  onRemove={() => setSetting({
                    ...setting,
                    allowed_domains: setting.allowed_domains.filter((item) => item !== domain),
                  })}
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
                onChange={(event) => setDraftDomain(event.target.value)}
                onKeyDown={onDomainKey}
                placeholder="例如: gmail.com"
              />
            </div>
            <div className="flex items-end">
              <Button type="button" icon="plus" onClick={addDomain}>添加</Button>
            </div>
          </div>
          <div>
            <Button type="submit" variant="ghost" icon="save" disabled={busy}>保存邮箱域名白名单设置</Button>
          </div>
        </form>
      )}
    </HudPanel>
  )
}
