import { useState, type FormEvent } from 'react'
import { apiFetch, type SessionLifetimeSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice } from '@chenxing/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, validateIntegerWithinRange, type SettingsPanelProps } from './panel'

const MAX_SESSION_TTL_SECONDS = 90 * 24 * 60 * 60
const MAX_SESSION_IDLE_TIMEOUT_SECONDS = 30 * 24 * 60 * 60
const DEFAULT_SESSION_TTL_SECONDS = 14 * 24 * 60 * 60
const FIELD_SPECS = [
  { key: 'session_ttl_seconds', label: '最长登录有效期（秒）', hint: '默认 14 天；这是会话的绝对截止时间。', maximum: MAX_SESSION_TTL_SECONDS },
  { key: 'session_idle_timeout_seconds', label: '无操作保持时间（秒）', hint: '默认 14 天；打开网页后长时间不操作也不会因空闲被登出。', maximum: MAX_SESSION_IDLE_TIMEOUT_SECONDS },
] as const

export function SessionLifetimePanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [draft, setDraft] = useState<Record<string, string> | null>(null)
  const [savedDraft, setSavedDraft] = useState<Record<string, string> | null>(null)
  const [busy, setBusy] = useState(false)
  const { loading } = useSettingsResource<SessionLifetimeSetting>({
    path: '/api/v1/admin/settings/session-lifetime',
    onMessage,
    failureMessage: '浏览器会话有效期加载失败。',
    apply: (value) => {
      const next = Object.fromEntries(FIELD_SPECS.map(({ key }) => [key, String(value[key])]))
      setDraft(next)
      setSavedDraft(next)
    },
  })
  const dirty = Boolean(savedDraft && !settingsEqual(draft, savedDraft))
  useDirtyReport(dirty, onDirtyChange)

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !draft) return
    const payload: Record<string, number> = {}
    for (const { key, label, maximum } of FIELD_SPECS) {
      const result = validateIntegerWithinRange(draft[key] ?? '', label, maximum)
      if ('error' in result) return onMessage(result.error, 'warning')
      payload[key] = result.value
    }
    setBusy(true)
    try {
      const updated = await apiFetch<SessionLifetimeSetting>('/api/v1/admin/settings/session-lifetime', {
        method: 'PUT', body: JSON.stringify(payload),
      })
      const next = Object.fromEntries(FIELD_SPECS.map(({ key }) => [key, String(updated[key])]))
      setDraft(next)
      setSavedDraft(next)
      onMessage('登录保持时间已保存；只影响之后新签发的登录会话。', 'warning')
    } catch (reason) {
      onMessage(reason instanceof Error ? reason.message : '登录保持时间保存失败。', 'warning')
    } finally { setBusy(false) }
  }

  return <HudPanel>
    <h2 className="chenxing-h2 flex items-center gap-2"><Icon name="clock-3" className="text-[var(--chenxing-cyan)]" size={18} />登录保持时间</h2>
    <p className="chenxing-caption mt-1.5">默认均为 14 天。修改只影响之后新签发的登录会话，当前已登录会话仍按原到期时间执行。</p>
    {loading || !draft ? <div className="mt-5"><Notice>正在加载登录保持时间。</Notice></div> : <form className="mt-5" noValidate onSubmit={save}>
      <fieldset disabled={busy} className="flex flex-col gap-4 sm:max-w-md">
        {FIELD_SPECS.map(({ key, label, hint, maximum }) => <Field key={key} label={label} hint={`${hint} 默认 ${DEFAULT_SESSION_TTL_SECONDS} 秒，上限 ${maximum} 秒。`} type="number" inputMode="numeric" min="1" max={maximum} step="1" value={draft[key]} onChange={(event) => setDraft((current) => current ? { ...current, [key]: event.target.value } : current)} />)}
        <div><Button type="submit" icon="save" disabled={busy}>保存登录保持时间</Button></div>
      </fieldset>
    </form>}
  </HudPanel>
}
