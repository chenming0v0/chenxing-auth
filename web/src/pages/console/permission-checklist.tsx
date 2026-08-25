import { useId } from 'react'
import { Icon, Switch } from '../../components/ui'
import { permissionChoices, type OAuthPermission } from '../../oauth-permissions'

const HINT = '勾选后，授权确认页会向用户展示这些权限。至少选择一项。'

function PermissionRow({
  item,
  checked,
  onChange,
}: {
  item: OAuthPermission
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.4)] px-4 py-3">
      <div className="min-w-0">
        <p className="chenxing-body text-sm font-semibold">
          {item.title}{' '}
          <span className="chenxing-mono text-[11px] font-normal text-[var(--chenxing-muted-foreground)]">{item.scope}</span>
        </p>
        <p className="chenxing-caption mt-0.5">{item.desc}</p>
      </div>
      <div className="shrink-0">
        <Switch checked={checked} onChange={onChange} label={item.title} />
      </div>
    </div>
  )
}

export function PermissionChecklist({
  id,
  selected,
  onChange,
  errorText,
}: {
  id: string
  selected: string[]
  onChange: (scopes: string[]) => void
  errorText?: string
}) {
  const labelId = useId()
  const messageId = `${id}-message`
  const rows = permissionChoices(selected)
  const selectedSet = new Set(selected)

  function toggle(scope: string, checked: boolean) {
    if (checked) {
      onChange(selectedSet.has(scope) ? selected : [...selected, scope])
      return
    }
    onChange(selected.filter((item) => item !== scope))
  }

  return (
    <div>
      <p className="chenxing-label" id={labelId}>权限</p>
      <div
        id={id}
        role="group"
        aria-labelledby={labelId}
        aria-describedby={errorText || HINT ? messageId : undefined}
        aria-invalid={errorText ? true : undefined}
        aria-required="true"
        tabIndex={-1}
        className="flex flex-col gap-3 outline-none"
      >
        {rows.map((item) => (
          <PermissionRow
            key={item.scope}
            item={item}
            checked={selectedSet.has(item.scope)}
            onChange={(checked) => toggle(item.scope, checked)}
          />
        ))}
      </div>
      {errorText ? (
        <small className="chenxing-field-message" id={messageId}>
          <Icon name="circle-alert" size={13} className="shrink-0" />
          {errorText}
        </small>
      ) : (
        <small className="chenxing-caption mt-1.5 block" id={messageId}>{HINT}</small>
      )}
    </div>
  )
}
