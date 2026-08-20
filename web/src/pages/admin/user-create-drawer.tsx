import { useState, type FormEvent } from 'react'
import { ApiError, apiFetch, type AdminCreateUserInput, type PublicUser, type UserRole } from '../../api'
import { Drawer } from '../../components/drawer'
import { Button, Field, HudPanel, Notice, PasswordField } from '../../components/ui'
import { SelectField, type SelectOption } from '../../components/select'
import { useMutationLock } from '../../use-mutation-lock'

/* 校验规则与服务端 src/users/domain.rs 一致：用户名 3-64 字符，仅含 ASCII 字母、数字、
   点号、下划线或连字符且不能使用系统保留名，密码 10-128 字符，显示名称 ≤128 字符，
   长度一律按字符数而非字节数计。
   前端校验只为少一次往返，服务端仍是唯一判定方。 */
const USERNAME_MIN = 3
const USERNAME_MAX = 64
const USERNAME_SAFE = /^[A-Za-z0-9._-]+$/
const USERNAME_CONTROL = /\p{Cc}/u
const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'owner', 'root', 'security', 'service', 'support',
  'superadmin', 'superuser', 'sysadmin', 'system',
])
const PASSWORD_MIN = 10
const PASSWORD_MAX = 128
const DISPLAY_NAME_MAX = 128

const ROLE_OPTIONS: SelectOption[] = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
  { value: 'owner', label: 'Owner' },
]

const STATUS_OPTIONS: SelectOption[] = [
  { value: 'active', label: '已启用' },
  { value: 'disabled', label: '已禁用' },
]

type FormState = {
  username: string
  email: string
  password: string
  displayName: string
  role: UserRole
  status: 'active' | 'disabled'
}

/** 只有文本字段会产生校验错误；角色和状态是受控枚举，不可能填错。 */
type TextField = 'username' | 'email' | 'password' | 'displayName'
type FieldErrors = Partial<Record<TextField, string>>

const EMPTY_FORM: FormState = { username: '', email: '', password: '', displayName: '', role: 'user', status: 'active' }

/** 提交失败时用于聚焦第一个出错字段，顺序与表单视觉顺序一致。 */
const FIELD_ORDER: TextField[] = ['username', 'email', 'password', 'displayName']
const FIELD_ID: Record<TextField, string> = {
  username: 'create-user-username',
  email: 'create-user-email',
  password: 'create-user-password',
  displayName: 'create-user-display-name',
}

function charCount(value: string): number {
  return Array.from(value).length
}

/* 邮箱校验对齐服务端 src/users/email.rs 的 EmailAddress::parse 里能用纯 JS 完整复刻的
   结构规则：恰好一个 @、本地部分非空、全串无空白与控制字符、总长 ≤254；域名必须含点，
   每个标签 1..=63 个字符、总长 ≤253（首尾点与连续点都是空标签），且不含 WHATWG
   forbidden domain code points（对应服务端的 AsciiDenyList::URL）。
   IDNA 规范化与 Punycode 合法性（Unicode 域名的映射、编码后的长度上限）需要 idna
   实现，前端不复刻——这里只是结构预检，服务端仍是唯一判定方。 */
const MAX_EMAIL_LENGTH = 254
const MAX_DOMAIN_LENGTH = 253
const MAX_LABEL_LENGTH = 63
/** AsciiDenyList::URL 拒绝的 ASCII 集合中，空白与控制字符已在上方整体拦掉，剩下的在此列。 */
const FORBIDDEN_DOMAIN_CHARS = new Set(['#', '%', '/', ':', '<', '>', '?', '@', '[', '\\', ']', '^', '{', '|', '}'])

function looksLikeEmail(value: string): boolean {
  if (charCount(value) > MAX_EMAIL_LENGTH) return false
  // 空白与控制字符在邮箱里没有合法位置，与服务端 ForbiddenCharacter 判定一致。
  if (/[\p{Cc}\s]/u.test(value)) return false
  const at = value.indexOf('@')
  if (at <= 0 || at !== value.lastIndexOf('@')) return false
  const domain = value.slice(at + 1)
  if (domain.length === 0 || charCount(domain) > MAX_DOMAIN_LENGTH) return false
  // 域名至少一个点，且每个标签 1..=63 个字符：`a@b.`、`a@.b`、`a@b..c`
  // 都会在标签拆分时出现空标签或缺点而被拒。
  const labels = domain.split('.')
  if (labels.length < 2) return false
  if (labels.some((label) => label === '' || charCount(label) > MAX_LABEL_LENGTH)) return false
  return ![...domain].some((character) => FORBIDDEN_DOMAIN_CHARS.has(character))
}

function validate(form: FormState): FieldErrors {
  const errors: FieldErrors = {}
  const username = form.username.trim()
  if (!username) errors.username = '请填写用户名。'
  else if (USERNAME_CONTROL.test(form.username)) errors.username = '用户名不能包含控制字符。'
  else if (charCount(username) < USERNAME_MIN || charCount(username) > USERNAME_MAX) {
    errors.username = `用户名需要 ${USERNAME_MIN} 到 ${USERNAME_MAX} 个字符。`
  } else if (username.includes('@') || /\s/.test(username)) {
    errors.username = '用户名不能包含 @ 或空格。'
  } else if (!USERNAME_SAFE.test(username)) {
    errors.username = '用户名只能包含字母、数字、点号、下划线和连字符。'
  } else if (RESERVED_USERNAMES.has(username.toLowerCase())) {
    errors.username = '该用户名为系统保留名称，请更换。'
  }

  const email = form.email.trim()
  if (!email) errors.email = '请填写邮箱。'
  else if (!looksLikeEmail(email)) errors.email = '邮箱格式不正确，例如 name@example.com。'

  if (!form.password) errors.password = '请填写初始密码。'
  else if (charCount(form.password) < PASSWORD_MIN) errors.password = `密码至少需要 ${PASSWORD_MIN} 个字符。`
  else if (charCount(form.password) > PASSWORD_MAX) errors.password = `密码最多 ${PASSWORD_MAX} 个字符。`

  if (charCount(form.displayName.trim()) > DISPLAY_NAME_MAX) {
    errors.displayName = `显示名称最多 ${DISPLAY_NAME_MAX} 个字符。`
  }
  return errors
}

/* 冲突和越权在管理端要说清楚是哪一项，才能改对。这里不复用 api.ts 的
   通用文案：注册入口刻意含糊以避免账号枚举，而管理员本就能查询用户列表，
   同样含糊只会让人反复试错。 */
const CONFLICT_FIELD: Partial<Record<string, TextField>> = {
  username_already_registered: 'username',
  email_already_registered: 'email',
  email_domain_not_allowed: 'email',
  invalid_username: 'username',
  invalid_email: 'email',
  password_too_short: 'password',
  password_too_long: 'password',
  display_name_too_long: 'displayName',
}
const CONFLICT_MESSAGE: Partial<Record<string, string>> = {
  username_already_registered: '该用户名已被占用，请更换。',
  email_already_registered: '该邮箱已注册过账号，请更换。',
}

export function UserCreateDrawer({ canManageRoles, onClose, onCreated }: {
  canManageRoles: boolean
  onClose: () => void
  /** 建号成功后由页面刷新列表并给出提示；抽屉随即卸载，表单状态自然重置。 */
  onCreated: (user: PublicUser) => void
}) {
  const [form, setForm] = useState<FormState>(EMPTY_FORM)
  const [errors, setErrors] = useState<FieldErrors>({})
  const [message, setMessage] = useState('')
  const { busy: saving, run } = useMutationLock()

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((current) => ({ ...current, [key]: value }))
    // 改动即清掉该字段的旧错误，避免用户边改边被已修正的提示追着。
    if (key in FIELD_ID) setErrors((current) => ({ ...current, [key as TextField]: undefined }))
  }

  function focusFirstError(nextErrors: FieldErrors) {
    const first = FIELD_ORDER.find((field) => nextErrors[field])
    if (first) document.getElementById(FIELD_ID[first])?.focus()
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    setMessage('')
    const nextErrors = validate(form)
    setErrors(nextErrors)
    if (Object.values(nextErrors).some(Boolean)) {
      focusFirstError(nextErrors)
      return
    }

    const displayName = form.displayName.trim()
    const input: AdminCreateUserInput = {
      username: form.username.trim(),
      email: form.email.trim(),
      password: form.password,
      display_name: displayName || null,
      role: form.role,
      status: form.status,
    }
    await run(async () => {
      try {
        const user = await apiFetch<PublicUser>('/api/v1/admin/users', { method: 'POST', body: JSON.stringify(input) })
        onCreated(user)
      } catch (reason) {
        const code = reason instanceof ApiError ? reason.code : undefined
        const field = code ? CONFLICT_FIELD[code] : undefined
        const text = (code ? CONFLICT_MESSAGE[code] : undefined)
          ?? (reason instanceof Error ? reason.message : '用户创建失败，请稍后重试。')
        if (field) {
          const nextFieldErrors = { [field]: text } as FieldErrors
          setErrors(nextFieldErrors)
          focusFirstError(nextFieldErrors)
        } else if (reason instanceof ApiError && reason.status === 403) {
          setMessage('当前管理身份不能创建该角色的账号，请改用普通用户，或由 Owner 操作。')
        } else {
          setMessage(text)
        }
      }
    })
  }

  return (
    <Drawer
      title="添加用户"
      description="由管理员直接建号，创建后账号立即可用，密码请通过安全渠道转交本人。"
      onClose={onClose}
      onSubmit={(event) => void submit(event)}
      busy={saving}
      footer={
        <>
          <Button type="button" variant="ghost" onClick={onClose} disabled={saving}>取消</Button>
          <Button type="submit" icon="user-plus" disabled={saving}>{saving ? '创建中…' : '创建用户'}</Button>
        </>
      }
    >
      {message ? <Notice tone="warning">{message}</Notice> : null}

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">账号信息</p>
        <Field
          label="用户名"
          id={FIELD_ID.username}
          icon="user"
          placeholder="stardust"
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="none"
          value={form.username}
          onChange={(event) => update('username', event.target.value)}
          errorText={errors.username}
          hint={`${USERNAME_MIN}-${USERNAME_MAX} 个字符，仅含字母、数字、点号、下划线和连字符，服务端会转为小写。`}
        />
        <Field
          label="邮箱"
          id={FIELD_ID.email}
          icon="mail"
          type="email"
          placeholder="stardust@example.com"
          autoComplete="off"
          spellCheck={false}
          autoCapitalize="none"
          value={form.email}
          onChange={(event) => update('email', event.target.value)}
          errorText={errors.email}
          hint="用于登录与通知，需要在系统内唯一。"
        />
        <PasswordField
          label="初始密码"
          id={FIELD_ID.password}
          icon="lock-keyhole"
          autoComplete="new-password"
          value={form.password}
          onChange={(event) => update('password', event.target.value)}
          errorText={errors.password}
          hint={`${PASSWORD_MIN}-${PASSWORD_MAX} 个字符，仅以哈希形式存储，创建后无法再查看。`}
        />
        <Field
          label="显示名称（选填）"
          id={FIELD_ID.displayName}
          icon="sparkles"
          placeholder="星尘"
          autoComplete="off"
          value={form.displayName}
          onChange={(event) => update('displayName', event.target.value)}
          errorText={errors.displayName}
          hint={`留空则界面上显示用户名，最多 ${DISPLAY_NAME_MAX} 个字符。`}
        />
      </HudPanel>

      <HudPanel className="space-y-4 !p-5">
        <p className="chenxing-label !mb-0">权限与状态</p>
        <div className="grid gap-4 sm:grid-cols-2">
          <SelectField
            label="角色"
            icon="shield"
            value={form.role}
            onChange={(value) => update('role', value as UserRole)}
            // 缺少 manage_roles 时后端会以 403 拒绝提权，这里先禁用对应选项，
            // 避免用户填完整张表单才撞到权限错误。
            options={ROLE_OPTIONS.map((option) => ({ ...option, disabled: !canManageRoles && option.value !== 'user' }))}
            hint={canManageRoles ? '管理员和 Owner 会获得后台权限，请谨慎授予。' : '当前管理身份没有 manage_roles 权限，只能创建普通用户。'}
          />
          <SelectField
            label="状态"
            icon="activity"
            value={form.status}
            onChange={(value) => update('status', value as 'active' | 'disabled')}
            options={STATUS_OPTIONS}
            hint="选择已禁用则账号建好后暂时无法登录。"
          />
        </div>
      </HudPanel>
    </Drawer>
  )
}
