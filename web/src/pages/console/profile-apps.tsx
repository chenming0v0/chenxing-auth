import { useEffect, useState, type FormEvent } from 'react'
import { Link, useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, ApiError, type AuthorizedOAuthApp, type SessionItem, type UserMe } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Chip, EmptyState, Field, HudPanel, Icon, Notice, PageIntro, PasswordField } from '../../components/ui'
import { ProfileAvatar, type MessageTone } from './profile-avatar'
import { formatDate } from '../../data'
import logoSrc from '../../assets/logo.png'

const PASSWORD_MIN_LENGTH = 10
const PASSWORD_MAX_LENGTH = 128
// 服务端 validate_display_name 先 trim 再按 code point 计数，上限 128。
const DISPLAY_NAME_MAX_LENGTH = 128
// HTML maxLength counts UTF-16 code units; two units per code point is the safe upper bound.
const PASSWORD_MAX_INPUT_LENGTH = PASSWORD_MAX_LENGTH * 2
const DISPLAY_NAME_MAX_INPUT_LENGTH = DISPLAY_NAME_MAX_LENGTH * 2

function codePointLength(value: string): number {
  return Array.from(value).length
}

function limitByCodePoints(value: string, maxLength: number): string {
  return Array.from(value).slice(0, maxLength).join('')
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
  /* 撤销在途的会话 id。与 AuthorizedApps 的 busyClientId 同款约定：
     null 表示无在途请求，非 null 期间所有撤销按钮禁用，防止快速连点并发 DELETE。 */
  const [busySessionId, setBusySessionId] = useState<number | null>(null)
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
    // 与服务端 validate_display_name 同款复核：先 trim 再按 code point 计数。
    // 输入虽已被 limitByCodePoints 截断，提交前仍兜底检查一次（粘贴/自动填充可绕过 maxLength）。
    if (codePointLength(displayName.trim()) > DISPLAY_NAME_MAX_LENGTH) {
      warn(`显示名称不能超过 ${DISPLAY_NAME_MAX_LENGTH} 个字符。`)
      return
    }
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
    const newPasswordLength = codePointLength(newPassword)
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
    setBusySessionId(session.id)
    setNotice(null)
    try {
      await apiFetch<void>(`/api/v1/auth/sessions/${session.id}`, { method: 'DELETE' })
    } catch (error) {
      // 404 表示会话已不存在（重复撤销或他处已撤销），与撤销成功等价，不算失败。
      if (!(error instanceof ApiError && error.status === 404)) {
        warn(error instanceof Error ? error.message : '会话撤销失败。')
        return
      }
    } finally {
      setBusySessionId(null)
    }
    if (session.current) { clear(); navigate('/login?returnTo=%2Fconsole%2Fprofile'); return }
    loadSessions()
  }

  const name = user?.display_name || user?.username || '用户'

  return (
    <ConsoleLayout>
      <section className="space-y-6 pt-2">
        <HudPanel className="is-starfield">
          {/* 淡化 logo 只在卡片右上角露出一角：裁切层单独 overflow-hidden，
              不能直接给面板加 overflow-hidden，否则会裁掉 ::before/::after 的青色角标。
              辉光层参照原型设计：右上角一道径向泛光衬在 logo 底下，金色泛光营造温暖的辰星印记。 */}
          <div className="pointer-events-none absolute inset-0 overflow-hidden rounded-[var(--chenxing-radius-lg)]" aria-hidden="true">
            <div className="absolute inset-0 bg-[radial-gradient(70%_140%_at_88%_0%,rgba(245,199,106,0.16),transparent_65%)]" />
            <img src={logoSrc} alt="" className="absolute -right-6 -top-10 h-48 w-48 opacity-[0.07] blur-[1px]" />
          </div>
          <div className="relative flex flex-col gap-6 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex items-start gap-5">
              <ProfileAvatar user={user} name={name} onMessage={notify} refresh={refresh} />
              <div className="space-y-2.5 pt-1">
                <div className="flex flex-wrap items-center gap-3">
                  <h1 className="chenxing-h1">{name}</h1>
                  <Badge tone="gold"><Icon name="star" size={13} />{user?.role || 'user'}</Badge>
                  <Badge tone="success"><Icon name="shield-check" size={13} />身份已验证</Badge>
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
              <Field label="显示名称" value={displayName} onChange={(event) => setDisplayName(limitByCodePoints(event.target.value, DISPLAY_NAME_MAX_LENGTH))} maxLength={DISPLAY_NAME_MAX_INPUT_LENGTH} hint={`最多 ${DISPLAY_NAME_MAX_LENGTH} 个 Unicode 字符。`} />
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
                <PasswordField label="新密码" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(limitByCodePoints(event.target.value, PASSWORD_MAX_LENGTH))} maxLength={PASSWORD_MAX_INPUT_LENGTH} required hint={`长度为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个 Unicode 字符。`} />
                <PasswordField label="确认新密码" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(limitByCodePoints(event.target.value, PASSWORD_MAX_LENGTH))} maxLength={PASSWORD_MAX_INPUT_LENGTH} required error={codePointLength(confirmPassword) > 0 && confirmPassword !== newPassword} hint={codePointLength(confirmPassword) > 0 && confirmPassword !== newPassword ? '两次输入的新密码不一致。' : '再次输入新密码以确认。'} />
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
                  <Button variant="danger" icon="x" disabled={busySessionId !== null} onClick={() => void revokeSession(session)}>撤销</Button>
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
  /* 提示语连同语气一起存，撤销成功显式写 success，不用文案子串反推语气。 */
  const [notice, setNotice] = useState<{ text: string; tone: MessageTone } | null>(null)
  const [busyClientId, setBusyClientId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const notify = (text: string, tone: MessageTone) => setNotice({ text, tone })
  const warn = (text: string) => notify(text, 'warning')

  /* 整页加载：重置 loading 与提示，失败时给出警告。 */
  async function loadApps(): Promise<void> {
    setLoading(true)
    setNotice(null)
    try {
      const response = await apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps')
      setApps(response.items)
    } catch (reason) {
      warn(reason instanceof Error ? reason.message : '应用列表加载失败。')
    } finally {
      setLoading(false)
    }
  }

  /* 静默刷新：不重置 loading、不覆盖提示。撤销成功的提示必须先于刷新写入，
     刷新失败时旧列表与新提示并存，成功事实不被掩盖；下次进入页面列表自然一致。 */
  async function refreshAppsSilently(): Promise<void> {
    try {
      const response = await apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps')
      setApps(response.items)
    } catch {
      // 静默失败：保留旧列表，撤销成功的提示不被刷新错误覆盖。
    }
  }

  useEffect(() => { void loadApps() }, [])

  async function revokeApp(app: AuthorizedOAuthApp) {
    if (!window.confirm(`确认撤销“${app.client_name}”的授权吗？撤销后，该应用将立即失去访问账户数据的权限，若要继续使用，必须重新授权。`)) return
    setBusyClientId(app.client_id)
    setNotice(null)
    try {
      await apiFetch<void>(`/api/v1/auth/authorized-apps/${encodeURIComponent(app.client_id)}`, { method: 'DELETE' })
      /* 撤销成功与列表刷新解耦：DELETE 成功就无条件提示成功，刷新失败不再掩盖成功事实。
         旧实现用 loadApps 的返回值决定是否提示，刷新失败时用户只看到
         “应用列表加载失败”，误以为撤销失败而重复点击，触发多余的重复 DELETE。 */
      notify('应用授权已撤销。', 'success')
      await refreshAppsSilently()
    } catch (reason) {
      warn(reason instanceof Error ? reason.message : '应用授权撤销失败。')
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
      {notice ? <div className="mb-4"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}
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
