import { useRef, useState, type FormEvent } from 'react'
import { apiFetch, type IssuerSettingResponse, type UpdateIssuerSetting } from '../../../api'
import { Button, Field, HudPanel, Icon, Notice } from '@chenxing/ui'
import { settingsEqual, useDirtyReport, useSettingsResource, type SettingsPanelProps } from './panel'

function validateIssuer(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return 'Issuer 不能为空。'
  let url: URL
  try {
    url = new URL(trimmed)
  } catch {
    return 'Issuer 必须是完整的 http(s) URL。'
  }
  if (!['http:', 'https:'].includes(url.protocol)
    || !url.hostname
    || url.username
    || url.password
    || url.pathname !== '/'
    || url.search
    || url.hash) {
    return 'Issuer 必须是无凭据、无路径、无查询和片段的 http(s) 根 URL。'
  }
  return null
}

function phaseLabel(phase: IssuerSettingResponse['phase']): string {
  if (phase === 'issuer_loaded') return '已加载'
  if (phase === 'issuer_invalid') return '运行时无效'
  return '等待配置'
}

export function IssuerPanel(props: SettingsPanelProps) {
  const [value, setValue] = useState('')
  const [savedValue, setSavedValue] = useState('')
  const [setting, setSetting] = useState<IssuerSettingResponse | null>(null)
  const [busy, setBusy] = useState(false)
  const draftRef = useRef({ value, savedValue })
  draftRef.current = { value, savedValue }
  const [validationError, setValidationError] = useState<string | null>(null)

  const { loading, failed, reload } = useSettingsResource<IssuerSettingResponse>({
    path: '/api/v1/admin/settings/issuer',
    onMessage: props.onMessage,
    failureMessage: 'Issuer 设置加载失败。',
    apply: (next) => {
      const nextValue = next.persisted?.value ?? next.loaded?.value ?? ''
      setSetting(next)
      const draftIsClean = draftRef.current.value === draftRef.current.savedValue
      if (draftIsClean) {
        setValue(nextValue)
        setSavedValue(nextValue)
      }
      setValidationError(null)
    },
  })

  const dirty = Boolean(setting && !settingsEqual(value, savedValue))
  useDirtyReport(dirty, props.onDirtyChange)

  async function save(event: FormEvent) {
    event.preventDefault()
    if (busy || !setting) return
    const normalized = value.trim()
    const error = validateIssuer(normalized)
    if (error) {
      setValidationError(error)
      props.onMessage(error, 'warning')
      return
    }
    const current = setting.persisted
    const changing = Boolean(current && current.value !== normalized)
    if (changing && !window.confirm('修改 Issuer 会改变 OIDC 的 iss 和 Discovery 地址，并可能使既有 RP 配置失效。确认继续吗？')) return
    const payload: UpdateIssuerSetting = {
      value: normalized,
      expected_generation: current?.generation ?? 0,
      confirm: changing,
    }
    setBusy(true)
    try {
      const next = await apiFetch<IssuerSettingResponse>('/api/v1/admin/settings/issuer', {
        method: 'PUT',
        body: JSON.stringify(payload),
      })
      const nextValue = next.persisted?.value ?? next.loaded?.value ?? normalized
      setSetting(next)
      setValue(nextValue)
      setSavedValue(nextValue)
      setValidationError(null)
      props.onMessage('Issuer 设置已保存并热生效。')
    } catch (reason) {
      props.onMessage(reason instanceof Error ? reason.message : 'Issuer 设置保存失败。', 'warning')
    } finally {
      setBusy(false)
    }
  }

  return (
    <HudPanel>
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="chenxing-h2 flex items-center gap-2">
            <Icon name="globe-2" className="text-[var(--chenxing-cyan)]" size={18} />
            OIDC Issuer
          </h2>
          <p className="chenxing-caption mt-1.5">Owner 专属。保存后当前进程和其他副本会按 generation 收敛。</p>
        </div>
        <Button variant="ghost" icon="refresh-cw" disabled={loading || busy} onClick={() => void reload()} aria-label="刷新 Issuer 状态">
          刷新
        </Button>
      </div>
      {loading ? (
        <div className="mt-5"><Notice>正在加载 Issuer 状态。</Notice></div>
      ) : failed || !setting ? (
        <div className="mt-5 flex flex-col items-start gap-3">
          <Notice tone="warning">Issuer 设置暂时无法加载。</Notice>
          <Button icon="refresh-cw" onClick={() => void reload()} aria-label="重新加载 Issuer 设置">
            重新加载
          </Button>
        </div>
      ) : (
        <form className="mt-5 flex flex-col gap-4" noValidate onSubmit={save}>
          <Field
            label="Issuer 根 URL"
            type="url"
            value={value}
            disabled={busy}
            error={Boolean(validationError)}
            errorText={validationError ?? undefined}
            hint="例如 https://auth.example.com；不能包含路径、查询、片段或凭据。"
            onChange={(event) => {
              setValue(event.target.value)
              setValidationError(null)
            }}
          />
          <div className="grid gap-3 sm:grid-cols-3">
            <div>
              <p className="chenxing-label">持久化状态</p>
              <p className="chenxing-caption mt-1">{setting.persisted ? `generation ${setting.persisted.generation}` : '未配置'}</p>
            </div>
            <div>
              <p className="chenxing-label">运行时状态</p>
              <p className="chenxing-caption mt-1">{setting.loaded ? `generation ${setting.loaded.generation}` : '未加载'}</p>
            </div>
            <div>
              <p className="chenxing-label">阶段</p>
              <p className="chenxing-caption mt-1">{phaseLabel(setting.phase)}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Button type="submit" icon="save" disabled={busy || !dirty}>
              保存 Issuer
            </Button>
            {dirty ? <span className="chenxing-caption">有未保存修改</span> : null}
          </div>
        </form>
      )}
    </HudPanel>
  )
}
