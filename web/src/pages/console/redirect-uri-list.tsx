import { forwardRef, useImperativeHandle, useState, type KeyboardEvent } from 'react'
import { Button, Field, Icon } from '@chenxing/ui'
import { REDIRECT_URI_RULE_MESSAGE, redirectUriProblem } from './developer-shared'

/** 与后端 `DEFAULT_MAX_REDIRECT_URIS` 对齐；前端只做即时拒绝，服务端仍是权威上限。 */
export const MAX_REDIRECT_URIS = 10

export type RedirectUriListHandle = {
  /** 提交前把输入框里未确认的草稿尝试写入列表。失败时草稿留在输入框。 */
  commitDraft: () => { uris: string[]; error?: string }
}

function commitRedirectUri(uris: string[], raw: string): { uris: string[]; error?: string } {
  const value = raw.trim()
  if (!value) return { uris }
  if (uris.includes(value)) return { uris, error: '该 Redirect URI 已添加。' }
  if (uris.length >= MAX_REDIRECT_URIS) return { uris, error: `最多添加 ${MAX_REDIRECT_URIS} 个 Redirect URI。` }
  const reason = redirectUriProblem(value)
  if (reason) return { uris, error: `「${value}」${reason}。${REDIRECT_URI_RULE_MESSAGE}` }
  return { uris: [...uris, value] }
}

export const RedirectUriList = forwardRef<RedirectUriListHandle, {
  id: string
  uris: string[]
  onChange: (uris: string[]) => void
  errorText?: string
  disabled?: boolean
}>(function RedirectUriList({ id, uris, onChange, errorText, disabled = false }, ref) {
  const [draft, setDraft] = useState('')
  const [localError, setLocalError] = useState('')
  const displayError = localError || errorText
  const messageId = `${id}-message`

  function applyCommit(raw: string): { uris: string[]; error?: string } {
    const result = commitRedirectUri(uris, raw)
    if (result.error) {
      setLocalError(result.error)
      return result
    }
    if (result.uris !== uris) {
      onChange(result.uris)
      setDraft('')
      setLocalError('')
    }
    return result
  }

  useImperativeHandle(ref, () => ({
    commitDraft: () => applyCommit(draft),
  }), [draft, uris, onChange])

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key !== 'Enter' || event.nativeEvent.isComposing) return
    event.preventDefault()
    if (!disabled) applyCommit(draft)
  }

  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1">
          <Field
            label="Redirect URI"
            id={id}
            icon="link"
            type="url"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="输入后按回车添加"
            value={draft}
            disabled={disabled}
            error={Boolean(displayError)}
            aria-describedby={messageId}
            onChange={(event) => {
              setDraft(event.target.value)
              if (localError) setLocalError('')
            }}
            onKeyDown={onKeyDown}
          />
        </div>
        <Button type="button" icon="plus" className="w-full sm:w-auto" onClick={() => applyCommit(draft)} disabled={disabled}>
          添加
        </Button>
      </div>
      {displayError ? (
        <small className="chenxing-field-message" id={messageId}>
          <Icon name="circle-alert" size={13} className="shrink-0" />
          {displayError}
        </small>
      ) : (
        <small className="chenxing-caption mt-1.5 block" id={messageId}>{REDIRECT_URI_RULE_MESSAGE}</small>
      )}
      {uris.length ? (
        <ul className="mt-3 flex flex-col gap-2" aria-label="已添加的 Redirect URI">
          {uris.map((uri) => (
            <li
              key={uri}
              className="flex items-center gap-3 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] py-2 pl-4 pr-2"
            >
              <span className="chenxing-mono min-w-0 flex-1 truncate text-sm" title={uri}>{uri}</span>
              <button
                type="button"
                className="chenxing-icon-btn shrink-0"
                aria-label={`移除 ${uri}`}
                disabled={disabled}
                onClick={() => onChange(uris.filter((item) => item !== uri))}
              >
                <Icon name="x" size={16} />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="chenxing-caption mt-3">尚未添加 Redirect URI。</p>
      )}
    </div>
  )
})
