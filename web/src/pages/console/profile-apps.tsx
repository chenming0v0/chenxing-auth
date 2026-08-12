import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, type AuthorizedOAuthApp, type SessionItem, type UserMe } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Chip, EmptyState, Field, HudPanel, Icon, Notice, PageIntro, PasswordField } from '../../components/ui'
import { ProfileAvatar, type MessageTone } from './profile-avatar'
import { formatDate } from '../../data'

const PASSWORD_MIN_LENGTH = 10
const PASSWORD_MAX_LENGTH = 128
// HTML maxLength counts UTF-16 code units; two units per code point is the safe upper bound.
const PASSWORD_MAX_INPUT_LENGTH = PASSWORD_MAX_LENGTH * 2

function passwordCodePointLength(value: string): number {
  return Array.from(value).length
}

function limitPasswordInput(value: string): string {
  return Array.from(value).slice(0, PASSWORD_MAX_LENGTH).join('')
}

export function ConsoleProfile() {
  const { user, clear, refresh } = useAuth()
  const navigate = useNavigate()
  const [displayName, setDisplayName] = useState('')
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [showPassword, setShowPassword] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  /* 提示语连同语气一起存。早先的实现用 message.includes('已保存') 反推语气，
     每加一条成功提示都得记得让文案命中那个子串，是等着出错的写法。 */
  const [notice, setNotice] = useState<{ text: string; tone: MessageTone } | null>(null)
  const [busy, setBusy] = useState(false)
  const notify = (text: string, tone: MessageTone) => setNotice({ text, tone })
  const warn = (text: string) => notify(text, 'warning')

  useEffect(() => { setDisplayName(user?.display_name || '') }, [user?.display_name])
  const loadSessions = () => {
    void apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions')
      .then((response) => setSessions(response.items))
      .catch((reason: unknown) => warn(reason instanceof Error ? reason.message : '会话列表加载失败。'))
  }
  useEffect(() => { loadSessions() }, [])

  async function updateProfile(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    setBusy(true)
    try {
      await apiFetch<UserMe>('/api/v1/auth/me', { method: 'PATCH', body: JSON.stringify({ display_name: displayName || null }) })
      await refresh()
      notify('资料已保存。', 'success')
    } catch (error) {
      warn(error instanceof Error ? error.message : '资料保存失败。')
    } finally { setBusy(false) }
  }

  async function updatePassword(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    const newPasswordLength = passwordCodePointLength(newPassword)
    if (newPasswordLength < PASSWORD_MIN_LENGTH) { warn(`新密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`); return }
    if (newPasswordLength > PASSWORD_MAX_LENGTH) { warn(`新密码不能超过 ${PASSWORD_MAX_LENGTH} 个字符。`); return }
    if (newPassword !== confirmPassword) { warn('两次输入的新密码不一致。'); return }
    setBusy(true)
    try {
      await apiFetch<void>('/api/v1/auth/password', { method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) })
      clear()
      navigate('/login?returnTo=%2Fconsole%2Fprofile')
    } catch (error) {
      warn(error instanceof Error ? error.message : '密码修改失败。')
    } finally { setBusy(false) }
  }

  async function revokeSession(session: SessionItem) {
    if (!window.confirm(session.current ? '撤销当前会话后需要重新登录，继续吗？' : '确认撤销这个会话吗？')) return
    setNotice(null)
    try {
      await apiFetch<void>(`/api/v1/auth/sessions/${session.id}`, { method: 'DELETE' })
      if (session.current) { clear(); navigate('/login?returnTo=%2Fconsole%2Fprofile'); return }
      loadSessions()
    } catch (error) {
      warn(error instanceof Error ? error.message : '会话撤销失败。')
    }
  }

  const name = user?.display_name || user?.username || '用户'

  return (
    <ConsoleLayout>
      <section className="space-y-6 pt-2">
        <HudPanel className="is-starfield">
          <div className="relative flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex items-start gap-5">
              <ProfileAvatar user={user} name={name} onMessage={notify} refresh={refresh} />
              <div className="space-y-2.5 pt-1">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="chenxing-h1">{name}</h1>
                  <Chip><Icon name="star" size={14} />{user?.role || 'user'}</Chip>
                  <Badge tone="success"><Icon name="shield-check" size={14} />身份已验证</Badge>
                </div>
                <p className="chenxing-caption chenxing-mono">{user?.email}</p>
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
                  <span className="chenxing-caption chenxing-mono">UID {user?.id ?? '—'}</span>
                  <span className="chenxing-caption">会话到期 {user ? formatDate(user.current_session_expires_at) : '—'}</span>
                </div>
              </div>
            </div>
          </div>
        </HudPanel>

        {notice ? <Notice tone={notice.tone}>{notice.text}</Notice> : null}

        <div className="grid gap-6 xl:grid-cols-2">
          <HudPanel>
            <div className="mb-5 flex items-center justify-between">
              <div><h2 className="chenxing-h2">基本资料</h2><p className="chenxing-caption mt-1">页面只展示公开用户资料。</p></div>
              <Icon name="user" className="text-[var(--chenxing-cyan)]" size={18} />
            </div>
            <form className="space-y-4" onSubmit={updateProfile}>
              <Field label="显示名称" value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
              <Field label="用户名" value={user?.username || ''} readOnly />
              <Field label="邮箱地址" type="email" value={user?.email || ''} readOnly hint="邮箱修改需要单独的验证流程。" />
              <Button type="submit" icon="check" disabled={busy}>保存资料</Button>
            </form>
          </HudPanel>
          <HudPanel>
            <div className="mb-5 flex items-center justify-between">
              <div><h2 className="chenxing-h2">安全设置</h2><p className="chenxing-caption mt-1">密码成功修改后所有会话都会被撤销。</p></div>
              <Icon name="lock-keyhole" className="text-[var(--chenxing-cyan)]" size={18} />
            </div>
            {showPassword ? (
              <form className="space-y-4" onSubmit={updatePassword}>
                <PasswordField label="当前密码" autoComplete="current-password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} required />
                <PasswordField label="新密码" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(limitPasswordInput(event.target.value))} maxLength={PASSWORD_MAX_INPUT_LENGTH} required hint={`长度为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个 Unicode 字符。`} />
                <PasswordField label="确认新密码" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(limitPasswordInput(event.target.value))} maxLength={PASSWORD_MAX_INPUT_LENGTH} required error={passwordCodePointLength(confirmPassword) > 0 && confirmPassword !== newPassword} hint={passwordCodePointLength(confirmPassword) > 0 && confirmPassword !== newPassword ? '两次输入的新密码不一致。' : '再次输入新密码以确认。'} />
                <div className="flex flex-wrap gap-3">
                  <Button type="submit" icon="key-round" disabled={busy}>确认修改</Button>
                  <Button type="button" variant="ghost" onClick={() => setShowPassword(false)}>取消</Button>
                </div>
              </form>
            ) : (
              <Button variant="ghost" icon="key-round" onClick={() => setShowPassword(true)}>修改密码</Button>
            )}
          </HudPanel>
        </div>

        <HudPanel>
          <div className="mb-5 flex items-center justify-between">
            <div><h2 className="chenxing-h2">活跃会话</h2><p className="chenxing-caption mt-1">只显示会话时间和当前标记，不展示 IP、User-Agent 或 payload。</p></div>
            <Icon name="lock" className="text-[var(--chenxing-cyan)]" size={18} />
          </div>
          {sessions.length ? (
            <div className="space-y-3">
              {sessions.map((session) => (
                <div key={session.id} className="flex flex-wrap items-center gap-4 rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] p-4">
                  <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-[var(--chenxing-cyan-soft)] text-[var(--chenxing-cyan)]"><Icon name="shield-check" size={16} /></span>
                  <div className="min-w-0 flex-1">
                    <p className="chenxing-body text-sm font-semibold">{session.current ? '当前会话' : '其他会话'}</p>
                    <p className="chenxing-caption chenxing-mono">创建于 {formatDate(session.created_at)} · 到期 {formatDate(session.expires_at)}</p>
                  </div>
                  {session.current ? <Badge tone="success">当前</Badge> : null}
                  <Button variant="danger" icon="x" onClick={() => void revokeSession(session)}>撤销</Button>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon="lock" title="暂无活跃会话" />
          )}
        </HudPanel>
      </section>
    </ConsoleLayout>
  )
}

export function AuthorizedApps() {
  const [apps, setApps] = useState<AuthorizedOAuthApp[]>([])
  const [message, setMessage] = useState('')
  const [busyClientId, setBusyClientId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  async function loadApps(): Promise<boolean> {
    setLoading(true)
    setMessage('')
    try {
      const response = await apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps')
      setApps(response.items)
      return true
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '应用列表加载失败。')
      return false
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void loadApps() }, [])

  async function revokeApp(app: AuthorizedOAuthApp) {
    if (!window.confirm(`确认撤销“${app.client_name}”的授权吗？撤销后，该应用将立即失去访问账户数据的权限，若要继续使用，必须重新授权。`)) return
    setBusyClientId(app.client_id)
    setMessage('')
    try {
      await apiFetch<void>(`/api/v1/auth/authorized-apps/${encodeURIComponent(app.client_id)}`, { method: 'DELETE' })
      if (await loadApps()) setMessage('应用授权已撤销。')
    } catch (reason) {
      setMessage(reason instanceof Error ? reason.message : '应用授权撤销失败。')
    } finally {
      setBusyClientId(null)
    }
  }

  const openScopes = apps.reduce((sum, app) => sum + app.scopes.length, 0)

  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Connections"
        title="已授权应用"
        description="管理已通过辰星通行证登录的第三方应用与其权限范围。"
        action={<Link className="chenxing-btn-ghost" to="/console/integrate">接入应用</Link>}
      />
      {message ? <div className="mb-4"><Notice tone={message.includes('已撤销') ? 'success' : 'warning'}>{message}</Notice></div> : null}
      <div className="mb-6 grid grid-cols-3 gap-3 sm:gap-4">
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">已授权应用</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">{loading ? '—' : apps.length}</p></HudPanel>
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">开放权限域</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">{loading ? '—' : openScopes}</p></HudPanel>
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">服务端记录</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">LIVE</p></HudPanel>
      </div>
      <div className="space-y-4">
        {apps.map((app) => (
          <HudPanel as="article" key={app.client_id} className="!p-5 sm:!p-6">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex items-start gap-4">
                  <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-[rgba(125,211,252,0.4)] bg-[rgba(56,189,248,0.12)] text-[var(--chenxing-cyan)] shadow-[var(--chenxing-shadow-cyan-float)]">
                    <Icon name="box" size={22} />
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="chenxing-h3">{app.client_name}</h3>
                      <Badge tone="success"><Icon name="check" size={12} />已连接</Badge>
                    </div>
                    <p className="chenxing-caption mt-1 chenxing-mono">{app.client_id}</p>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {app.scopes.map((scope) => <Chip key={scope}><Icon name="fingerprint" size={14} />{scope}</Chip>)}
                </div>
                <p className="chenxing-caption mt-3">最近授权 {formatDate(app.updated_at)}</p>
              </div>
              <div className="flex shrink-0 items-center gap-4 lg:flex-col lg:items-end lg:gap-3">
                <Button variant="ghost" icon="eye" disabled title="详情接口尚未提供">查看详情</Button>
                <Button variant="danger" icon="unlink" disabled={busyClientId !== null} onClick={() => void revokeApp(app)}>撤销授权</Button>
              </div>
            </div>
          </HudPanel>
        ))}
        {!loading && !apps.length ? (
          <HudPanel>
            <EmptyState icon="shield-check" title="暂无已授权应用" description="完成 OAuth 授权后，应用会显示在这里。" action={<Link className="chenxing-btn-primary mt-2" to="/console/playground">去授权测试</Link>} />
          </HudPanel>
        ) : null}
      </div>
    </ConsoleLayout>
  )
}
