import { useEffect, useState } from 'react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { apiFetch, type AuthorizationDecisionResponse, type PendingAuthorization } from '../api'
import { OAuthShell } from '../components/shells'
import { BrandMark, Icon, Notice } from '../components/ui'
import { initialOf } from '../data'

function useRequestId(): string | null {
  return new URLSearchParams(useLocation().search).get('request_id')
}

function appMark(name?: string) {
  return (name || 'A').trim().slice(0, 1).toUpperCase()
}

/**
 * 校验后端返回的跳转地址：只允许 http/https。
 * 后端响应一旦被污染，`javascript:` 之类的伪协议会在用户点「允许」时执行脚本，
 * 因此这里在导航前强制解析并检查协议；畸形输入让 `new URL` 抛错，统一按无效处理。
 */
function safeRedirectTarget(raw: string): string | null {
  try {
    const url = new URL(raw, window.location.origin)
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null
    return url.href
  } catch {
    return null
  }
}

function scopeMeta(scope: string): { title: string; desc: string } {
  if (scope === 'openid') return { title: '身份标识', desc: '获取你的唯一辰星 ID，用于识别账户身份' }
  if (scope === 'profile') return { title: '基本资料', desc: '查看你的昵称、头像与公开个人信息' }
  if (scope === 'email') return { title: '电子邮箱', desc: '读取与你账号关联的邮箱地址' }
  if (scope === 'offline_access') return { title: '离线访问', desc: '在你离线时刷新访问令牌' }
  return { title: scope, desc: '应用请求的额外权限范围' }
}

export function OAuthAccountPage() {
  const navigate = useNavigate()
  const requestId = useRequestId()
  const { user } = useAuth()
  const [pending, setPending] = useState<PendingAuthorization | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!requestId) {
      setMessage('授权请求缺少 request_id，请重新发起。')
      return
    }
    let active = true
    void apiFetch<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`)
      .then((value) => { if (active) setPending(value) })
      .catch((reason: unknown) => { if (active) setMessage(reason instanceof Error ? reason.message : '授权请求已失效。') })
    return () => { active = false }
  }, [requestId])

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region */}
      <div className="oauth-card chenxing-hud-panel" role="region" aria-label="选择辰星通行证账号">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">使用辰星通行证登录</span>
        </div>
        <div className="oauth-card-body">
          <div>
            <div className="oauth-app-mark" aria-hidden="true">{appMark(pending?.client_name)}</div>
            <h1 className="oauth-title">选择账号</h1>
            <p className="oauth-copy is-lead">
              以继续使用
              <span className="oauth-client-name">「{pending?.client_name || '接入应用'}」</span>
            </p>
          </div>
          <div>
            {message ? <Notice tone="warning">{message}</Notice> : null}
            {!message && !pending ? <Notice tone="info">正在读取授权请求…</Notice> : null}
            {pending ? (
              <>
                {/* 保留 ul/li + 原生 button/a 语义：原生控件自带键盘可达性，
                    不使用 listbox/option（那需要自行实现方向键与 aria-activedescendant） */}
                <ul className="oauth-list" aria-label="可选账号">
                  <li>
                    <button type="button" onClick={() => navigate(`/oauth/consent?request_id=${encodeURIComponent(pending.request_id)}`)}>
                      <span className="oauth-avatar">{initialOf(user?.display_name || user?.username)}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium text-[var(--chenxing-foreground)]">{user?.display_name || user?.username}</span>
                        <span className="chenxing-mono block truncate text-[12px] text-[var(--chenxing-muted-foreground)]">{user?.email} · {user?.role || 'User'}</span>
                      </span>
                      <Icon name="arrow-right" className="text-[var(--chenxing-muted-foreground)]" size={16} />
                    </button>
                  </li>
                  <li>
                    <Link to="/login" className="flex w-full items-center gap-3.5 border-0 bg-transparent px-4 py-3.5 text-left">
                      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-dashed border-[var(--chenxing-border-strong)] text-[var(--chenxing-muted-foreground)]">+</span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium text-[var(--chenxing-foreground)]">使用其他辰星通行证</span>
                        <span className="block text-[12px] text-[var(--chenxing-muted-foreground)]">登录另一个账号继续授权</span>
                      </span>
                    </Link>
                  </li>
                </ul>
                <p className="oauth-copy is-legal">
                  在使用该应用之前，你可以查看「{pending.client_name}」的<a href="#">隐私政策</a>和<a href="#">服务条款</a>。
                </p>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </OAuthShell>
  )
}

export function OAuthConsentPage() {
  const requestId = useRequestId()
  const { user } = useAuth()
  const [pending, setPending] = useState<PendingAuthorization | null>(null)
  const [message, setMessage] = useState('')
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (!requestId) {
      setMessage('授权请求缺少 request_id，请重新发起。')
      return
    }
    let active = true
    void apiFetch<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`)
      .then((value) => { if (active) setPending(value) })
      .catch((reason: unknown) => { if (active) setMessage(reason instanceof Error ? reason.message : '授权请求已失效。') })
    return () => { active = false }
  }, [requestId])

  async function decide(decision: 'approve' | 'deny') {
    if (!requestId || submitting) return
    setMessage('')
    setSubmitting(true)
    try {
      const response = await apiFetch<AuthorizationDecisionResponse>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`, {
        method: 'POST',
        body: JSON.stringify({ decision }),
      })
      const target = safeRedirectTarget(response.redirect_to)
      if (!target) {
        setMessage('授权跳转地址无效，已阻止本次跳转，请重新发起授权。')
        setSubmitting(false)
        return
      }
      window.location.assign(target)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '授权请求处理失败。')
      setSubmitting(false)
    }
  }

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region */}
      <div className="oauth-card chenxing-hud-panel" role="region" aria-label="辰星通行证授权确认">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">使用辰星通行证登录</span>
        </div>
        <div className="oauth-card-body">
          <div>
            <div className="oauth-app-mark" aria-hidden="true">{appMark(pending?.client_name)}</div>
            <h1 className="oauth-title">
              「{pending?.client_name || '接入应用'}」想要访问<br />你的辰星通行证
            </h1>
            <Link className="oauth-account" to={requestId ? `/oauth/account?request_id=${encodeURIComponent(requestId)}` : '/oauth/account'} aria-label={`切换账号：${user?.email || ''}`}>
              <span className="oauth-avatar">{initialOf(user?.display_name || user?.username)}</span>
              <span className="truncate text-[13px]">{user?.email || '当前会话'}</span>
              <Icon name="chevron-down" className="opacity-60" size={14} />
            </Link>
          </div>
          <div>
            {message ? <div className="mb-4"><Notice tone="warning">{message}</Notice></div> : null}
            {!message && !pending ? <Notice tone="info">正在读取授权摘要…</Notice> : null}
            {pending ? (
              <>
                <p className="oauth-copy">除非你确定「{pending.client_name}」是你信任的接入应用，否则请勿继续授权。</p>
                <p className="oauth-copy">如果该应用最近更新过权限范围，可能会再次要求你确认授权。</p>
                <p className="oauth-copy">本次请求将在 {pending.expires_in} 秒内失效，且只绑定当前 Session。</p>
                <div className="mt-5">
                  <div className="mb-2 text-[13px] font-medium text-[var(--chenxing-muted-foreground)]">授权后将获得以下权限</div>
                  {pending.scopes.map((scope) => {
                    const meta = scopeMeta(scope)
                    return (
                      <div className="oauth-scope" key={scope}>
                        <span className="oauth-scope-icon" aria-hidden="true"><Icon name="check" size={12} /></span>
                        <span>
                          <span className="block text-[13.5px] font-medium text-[var(--chenxing-foreground)]">
                            {meta.title} <span className="chenxing-mono text-[11px] text-[var(--chenxing-muted-foreground)]">{scope}</span>
                          </span>
                          <span className="mt-0.5 block text-xs leading-relaxed text-[var(--chenxing-muted-foreground)]">{meta.desc}</span>
                        </span>
                      </div>
                    )
                  })}
                </div>
                <div className="oauth-actions">
                  <button type="button" className="oauth-btn" disabled={submitting} onClick={() => void decide('deny')}>取消</button>
                  <button type="button" className="oauth-btn oauth-btn-primary" disabled={submitting} onClick={() => void decide('approve')}>允许</button>
                </div>
              </>
            ) : null}
          </div>
        </div>
      </div>
    </OAuthShell>
  )
}

export function OAuthRedirectPage() {
  const query = new URLSearchParams(useLocation().search)
  const hasError = query.has('error')
  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region。
          保留 aria-live 以便 SPA 内跳转到本页时播报授权结果 */}
      <div className="oauth-card chenxing-hud-panel" role="region" aria-live="polite" aria-label="辰星通行证授权结果">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">{hasError ? '授权未完成' : '授权完成 · 正在返回接入应用'}</span>
        </div>
        <div className="oauth-center">
          <div className="oauth-transfer" aria-hidden="true">
            <span className="oauth-transfer-mark">
              <BrandMark className="h-9 w-9 rounded-[10px] object-contain" />
            </span>
            <span className="oauth-beam" />
            <span className="oauth-transfer-mark is-client">A</span>
          </div>
          {hasError ? (
            <>
              <h1 className="oauth-title is-compact">授权没有完成</h1>
              <p className="oauth-copy is-notice">授权请求被拒绝或未完成。辰星不会在此页面展示授权码或 Token。</p>
              <div className="mt-6"><Link to="/console" className="oauth-btn oauth-btn-primary">返回控制台</Link></div>
            </>
          ) : (
            <>
              <div className="flex items-center justify-center gap-2 text-sm font-medium text-[var(--chenxing-foreground)]">
                <Icon name="refresh-cw" className="oauth-spin text-[var(--chenxing-cyan)]" size={15} />
                授权回调已收到
              </div>
              <p className="oauth-copy is-hint">回调参数已交给发起方处理，不会在浏览器中长期保留。</p>
              <div className="mt-6"><Link to="/console" className="chenxing-link">返回控制台</Link></div>
            </>
          )}
        </div>
      </div>
    </OAuthShell>
  )
}
