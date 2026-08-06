import { useState, type FormEvent } from 'react'
import { apiFetch, type PublicUser } from '../../api'
import { Button, Field, HudPanel, Icon, Notice, PasswordField } from '../../components/ui'
import { SelectField, type SelectOption } from '../../components/select'

const ROLE_OPTIONS: SelectOption[] = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
  { value: 'owner', label: 'Owner' },
]

const STATUS_OPTIONS: SelectOption[] = [
  { value: 'active', label: '已启用' },
  { value: 'disabled', label: '已禁用' },
]

type CreateUserInput = {
  username: string
  email: string
  password: string
  display_name: string | null
  role: string
  status: string
}

export function CreateUserDrawer({ onCreated, onClose }: { onCreated: () => void; onClose: () => void }) {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [role, setRole] = useState('user')
  const [status, setStatus] = useState('active')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(event: FormEvent) {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      const input: CreateUserInput = {
        username: username.trim(),
        email: email.trim(),
        password,
        display_name: displayName.trim() || null,
        role,
        status,
      }
      await apiFetch<PublicUser>('/api/v1/admin/users', { method: 'POST', body: JSON.stringify(input) })
      onCreated()
      onClose()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '用户创建失败。')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="chenxing-drawer-overlay is-open" onClick={onClose}>
      <div className="chenxing-drawer is-open" onClick={(event) => event.stopPropagation()}>
        <div className="chenxing-drawer-header">
          <div>
            <h2 className="chenxing-h2">添加用户</h2>
            <p className="chenxing-caption mt-1">管理员创建新辰星通行证账号。</p>
          </div>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onClose}>
            <Icon name="x" size={16} />
          </button>
        </div>
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={submit}>
          <div className="chenxing-drawer-body space-y-4">
            <HudPanel className="space-y-4 !p-5">
              <Notice tone="info">
                后端创建用户接口尚在开发中（
                <a className="underline" href="https://github.com/chenming0v0/chenxing-auth/issues/133" target="_blank" rel="noreferrer">
                  #133
                </a>
                ），提交后若报错请等待接口上线。
              </Notice>
              {error ? <Notice tone="warning">{error}</Notice> : null}
              <Field label="用户名" icon="user" placeholder="例如：stardust" value={username} onChange={(e) => setUsername(e.target.value)} required />
              <Field label="邮箱" icon="mail" type="email" placeholder="例如：star@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
              <PasswordField label="密码" icon="lock" placeholder="至少 8 个字符" value={password} onChange={(e) => setPassword(e.target.value)} required />
              <Field label="显示名称（可选）" icon="pencil" placeholder="留空则使用用户名" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
              <SelectField label="角色" icon="shield" value={role} onChange={setRole} options={ROLE_OPTIONS} />
              <SelectField label="初始状态" icon="activity" value={status} onChange={setStatus} options={STATUS_OPTIONS} />
            </HudPanel>
          </div>
          <div className="chenxing-drawer-footer">
            <Button type="button" variant="ghost" onClick={onClose}>
              取消
            </Button>
            <Button type="submit" icon="user-plus" disabled={busy}>
              {busy ? '创建中…' : '创建账号'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
