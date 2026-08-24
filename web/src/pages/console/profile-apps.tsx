import { useEffect, useRef, useState, type FormEvent } from 'react'
import { useNavigate } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, ApiError, type SessionItem, type UserMe } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, EmptyState, HudPanel, Icon, Notice } from '../../components/ui'
import { ProfileAvatar, type MessageTone } from './profile-avatar'
import { formatDate } from '../../data'
import logoSrc from '../../assets/logo.png'
import { AccountManagement } from './security'
import { ProfileEditorDialog } from './profile-editor-dialog'
import { EmailChangeDialog } from './email-change-dialog'
import { PasswordChangeDialog } from './password-change-dialog'
import { useMutationLock } from '../../use-mutation-lock'

const PASSWORD_MIN_LENGTH = 10
const PASSWORD_MAX_LENGTH = 128
// 服务端 validate_display_name 先 trim 再按 code point 计数，上限 128。
const DISPLAY_NAME_MAX_LENGTH = 128
const USERNAME_MIN_LENGTH = 3
const USERNAME_MAX_LENGTH = 64
const USERNAME_PATTERN = /^[a-z0-9._-]+$/
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
  const [username, setUsername] = useState('')
  const [profilePassword, setProfilePassword] = useState('')
  const [showProfileEditor, setShowProfileEditor] = useState(false)
  const [newEmail, setNewEmail] = useState('')
  const [emailPassword, setEmailPassword] = useState('')
  const [emailCode, setEmailCode] = useState('')
  const [emailChallengeId, setEmailChallengeId] = useState<string | null>(null)
  const [showEmailEditor, setShowEmailEditor] = useState(false)
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [showPassword, setShowPassword] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const emailChangeGeneration = useRef(0)
  /* 提示语连同语气一起存。早先的实现用 message.includes('已保存') 反推语气，
     每加一条成功提示都得记得让文案命中那个子串，是等着出错的写法。 */
  const [notice, setNotice] = useState<{ text: string; tone: MessageTone } | null>(null)
  const { busy, acquire, release, run } = useMutationLock()
  const profileRequestIdRef = useRef(0)
  /* 撤销在途的会话 id。与 AuthorizedApps 的 busyClientId 同款约定：
     null 表示无在途请求，非 null 期间所有撤销按钮禁用，防止快速连点并发 DELETE。 */
  const [busySessionId, setBusySessionId] = useState<number | null>(null)
  const sessionsRequestId = useRef(0)
  const notify = (text: string, tone: MessageTone) => setNotice({ text, tone })
  const warn = (text: string) => notify(text, 'warning')

  useEffect(() => {
    setDisplayName(user?.display_name || '')
    setUsername(user?.username || '')
  }, [user?.display_name, user?.username])
  const loadSessions = async () => {
    const requestId = ++sessionsRequestId.current
    try {
      const response = await apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions')
      if (requestId === sessionsRequestId.current) setSessions(response.items)
    } catch (reason: unknown) {
      if (requestId === sessionsRequestId.current) warn(reason instanceof Error ? reason.message : '会话列表加载失败。')
    }
  }
  useEffect(() => { void loadSessions() }, [])

  async function updateProfile(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    const normalizedUsername = username.trim().toLowerCase()
    const usernameChanged = Boolean(user) && normalizedUsername !== user?.username
    // 与服务端 validate_display_name 同款复核：先 trim 再按 code point 计数。
    // 输入虽已被 limitByCodePoints 截断，提交前仍兜底检查一次（粘贴/自动填充可绕过 maxLength）。
    if (codePointLength(displayName.trim()) > DISPLAY_NAME_MAX_LENGTH) {
      warn(`显示名称不能超过 ${DISPLAY_NAME_MAX_LENGTH} 个字符。`)
      return
    }
    if (normalizedUsername.length < USERNAME_MIN_LENGTH || normalizedUsername.length > USERNAME_MAX_LENGTH || !USERNAME_PATTERN.test(normalizedUsername)) {
      warn(`用户名需要 ${USERNAME_MIN_LENGTH}-${USERNAME_MAX_LENGTH} 位，只能包含小写字母、数字、点、下划线和连字符。`)
      return
    }
    if (usernameChanged && !profilePassword) {
      warn('修改用户名需要输入当前密码。')
      return
    }
    if (!acquire()) return
    const requestId = ++profileRequestIdRef.current
    try {
      const updated = await apiFetch<UserMe>('/api/v1/auth/me', {
        method: 'PATCH',
        redirectOn401: false,
        body: JSON.stringify({
          display_name: displayName.trim() || null,
          username: normalizedUsername,
          ...(usernameChanged ? { current_password: profilePassword } : {}),
        }),
      })
      if (requestId !== profileRequestIdRef.current) return
      if (updated.username !== normalizedUsername) {
        warn('服务端返回的用户名与本次修改不一致，请刷新后重试。')
        return
      }
      await refresh()
      if (requestId !== profileRequestIdRef.current) return
      setDisplayName(updated.display_name || '')
      setUsername(updated.username)
      setProfilePassword('')
      setShowProfileEditor(false)
      notify('账户资料已保存。', 'success')
    } catch (error) {
      if (requestId === profileRequestIdRef.current) warn(error instanceof Error ? error.message : '资料保存失败。')
    } finally { release() }
  }

  async function updatePassword(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    const newPasswordLength = codePointLength(newPassword)
    if (newPasswordLength < PASSWORD_MIN_LENGTH) { warn(`新密码至少需要 ${PASSWORD_MIN_LENGTH} 个字符。`); return }
    if (newPasswordLength > PASSWORD_MAX_LENGTH) { warn(`新密码不能超过 ${PASSWORD_MAX_LENGTH} 个字符。`); return }
    if (newPassword !== confirmPassword) { warn('两次输入的新密码不一致。'); return }
    await run(async () => {
      try {
        await apiFetch<void>('/api/v1/auth/password', { method: 'POST', redirectOn401: false, body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) })
        clear()
        navigate('/login?returnTo=%2Fconsole%2Fprofile')
      } catch (error) {
        warn(error instanceof Error ? error.message : '密码修改失败。')
      }
    })
  }

  async function revokeSession(session: SessionItem) {
    if (!window.confirm(session.current ? '撤销当前会话后需要重新登录，继续吗？' : '确认撤销这个会话吗？')) return
    setBusySessionId(session.id)
    setNotice(null)
    try {
      try {
        await apiFetch<void>(`/api/v1/auth/sessions/${session.id}`, { method: 'DELETE' })
      } catch (error) {
        // 404 表示会话已不存在（重复撤销或他处已撤销），与撤销成功等价，不算失败。
        if (!(error instanceof ApiError && error.status === 404)) {
          warn(error instanceof Error ? error.message : '会话撤销失败。')
          return
        }
      }
      if (session.current) { clear(); navigate('/login?returnTo=%2Fconsole%2Fprofile'); return }
      await loadSessions()
    } finally {
      setBusySessionId((current) => current === session.id ? null : current)
    }
  }

  const name = user?.display_name || user?.username || '用户'
  const usernameChanged = Boolean(user) && username.trim().toLowerCase() !== user?.username

  function resetProfileEditor() {
    setDisplayName(user?.display_name || '')
    setUsername(user?.username || '')
    setProfilePassword('')
  }

  function openProfileEditor() {
    resetProfileEditor()
    setShowProfileEditor(true)
  }

  function closeProfileEditor() {
    resetProfileEditor()
    setShowProfileEditor(false)
  }

  function resetEmailEditor() {
    emailChangeGeneration.current += 1
    setNewEmail('')
    setEmailPassword('')
    setEmailCode('')
    setEmailChallengeId(null)
    setNotice(null)
  }

  function openEmailEditor() {
    resetEmailEditor()
    setShowEmailEditor(true)
  }

  function closeEmailEditor() {
    resetEmailEditor()
    setShowEmailEditor(false)
  }

  function openPasswordEditor() {
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setShowPassword(true)
  }

  function closePasswordEditor() {
    setCurrentPassword('')
    setNewPassword('')
    setConfirmPassword('')
    setShowPassword(false)
  }

  async function requestEmailChange(event: FormEvent) {
    event.preventDefault()
    setNotice(null)
    const generation = emailChangeGeneration.current
    await run(async () => {
      try {
        if (!emailChallengeId) {
          const result = await apiFetch<{ challenge_id: string }>('/api/v1/auth/email-change/start', { method: 'POST', body: JSON.stringify({ new_email: newEmail.trim(), current_password: emailPassword }) })
          if (generation !== emailChangeGeneration.current) return
          setEmailChallengeId(result.challenge_id)
          notify('验证码已排队发送到新邮箱。', 'success')
        } else {
          await apiFetch<void>('/api/v1/auth/email-change/confirm', { method: 'POST', body: JSON.stringify({ challenge_id: emailChallengeId, code: emailCode }) })
          if (generation !== emailChangeGeneration.current) return
          clear()
          navigate('/login?returnTo=%2Fconsole%2Fprofile')
        }
      } catch (error) {
        if (generation !== emailChangeGeneration.current) return
        warn(error instanceof Error ? error.message : '邮箱变更失败。')
      }
    })
  }

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

        <AccountManagement
          userEmail={user?.email || '—'}
          profileSummary={`显示名称：${name} · 用户名：@${user?.username || '—'}`}
          profileAction={<Button variant="ghost" icon="pencil" onClick={openProfileEditor}>修改账户资料</Button>}
          emailAction={<Button variant="ghost" icon="mail" onClick={openEmailEditor}>更改邮箱</Button>}
          passwordAction={<Button variant="ghost" icon="key-round" onClick={openPasswordEditor}>修改密码</Button>}
        />

        {showProfileEditor ? (
          <ProfileEditorDialog
            displayName={displayName}
            username={username}
            password={profilePassword}
            busy={busy}
            usernameChangePending={usernameChanged}
            onDisplayName={(value) => setDisplayName(limitByCodePoints(value, DISPLAY_NAME_MAX_LENGTH))}
            onUsername={(value) => setUsername(value.toLowerCase().replace(/[^a-z0-9._-]/g, '').slice(0, USERNAME_MAX_LENGTH))}
            onPassword={setProfilePassword}
            onCancel={closeProfileEditor}
            onSubmit={updateProfile}
          />
        ) : null}

        {showEmailEditor ? (
          <EmailChangeDialog
            currentEmail={user?.email || '—'}
            newEmail={newEmail}
            password={emailPassword}
            code={emailCode}
            stage={emailChallengeId ? 'verify' : 'details'}
            busy={busy}
            onNewEmail={(value) => setNewEmail(value.slice(0, 254))}
            onPassword={setEmailPassword}
            onCode={setEmailCode}
            onCancel={closeEmailEditor}
            onSubmit={requestEmailChange}
          />
        ) : null}

        {showPassword ? (
          <PasswordChangeDialog
            currentPassword={currentPassword}
            newPassword={newPassword}
            confirmPassword={confirmPassword}
            busy={busy}
            maxInputLength={PASSWORD_MAX_INPUT_LENGTH}
            passwordHint={`长度为 ${PASSWORD_MIN_LENGTH}-${PASSWORD_MAX_LENGTH} 个 Unicode 字符。`}
            confirmError={codePointLength(confirmPassword) > 0 && confirmPassword !== newPassword}
            confirmHint={codePointLength(confirmPassword) > 0 && confirmPassword !== newPassword ? '两次输入的新密码不一致。' : '再次输入新密码以确认。'}
            onCurrentPassword={setCurrentPassword}
            onNewPassword={(value) => setNewPassword(limitByCodePoints(value, PASSWORD_MAX_LENGTH))}
            onConfirmPassword={(value) => setConfirmPassword(limitByCodePoints(value, PASSWORD_MAX_LENGTH))}
            onCancel={closePasswordEditor}
            onSubmit={updatePassword}
          />
        ) : null}

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
