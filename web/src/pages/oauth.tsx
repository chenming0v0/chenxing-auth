import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import {
  ApiError,
  apiFetch,
  loadAuthorizationRequest,
  loginRecoveryTarget,
  type AuthorizationDecisionResponse,
  type PendingAuthorization,
} from '../api'
import { OAuthShell } from '../components/shells'
import { BrandMark, HudPanel, Icon, Notice } from '../components/ui'
import { initialOf } from '../data'

function useRequestId(): string | null {
  return new URLSearchParams(useLocation().search).get('request_id')
}

/**
 * 读取待授权请求，并把「会话不再有效」收敛成一次带 `request_id` 的登录跳转。
 *
 * `loadAuthorizationRequest` 已经先绑后读，因此走到 401 说明浏览器当前确实没有
 * 可用会话（而不是绑定指向了旧会话）。此时必须带上 `request_id` 去登录页，
 * 登录页登录成功后才能重新绑定并回到确认页；丢掉它就会在登录页与确认页之间
 * 无限打转（#270）。
 *
 * 请求态（pending/message）在 requestId 变化时不会自动清空，调用方必须用
 * `key={requestId}` 重挂载消费组件（#330）：否则旧请求的同意信息会在新请求
 * 加载期间继续展示，用户看到的是 A、实际批准的是 B（consent spoofing）。
 */
function usePendingAuthorization(requestId: string | null): {
  pending: PendingAuthorization | null
  message: string
  setMessage: (message: string) => void
} {
  const navigate = useNavigate()
  const [pending, setPending] = useState<PendingAuthorization | null>(null)
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (!requestId) {
      setMessage('授权请求缺少 request_id，请重新发起。')
      return
    }
    let active = true
    void loadAuthorizationRequest(requestId)
      .then((value) => { if (active) setPending(value) })
      .catch((reason: unknown) => {
        if (!active) return
        if (reason instanceof ApiError && reason.status === 401) {
          // 会话失效是守卫性重定向（#326）：replace 当前条目，避免后退键
          // 回到 401 页面再次触发跳转，形成「登录页 ↔ 确认页」历史陷阱。
          navigate(loginRecoveryTarget(window.location.pathname, window.location.search), { replace: true })
          return
        }
        setMessage(reason instanceof Error ? reason.message : '授权请求已失效。')
      })
    return () => { active = false }
  }, [navigate, requestId])

  return { pending, message, setMessage }
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

/**
 * 把当前地址换成同路径的无查询版本（#196）。
 * OAuth 流程里的 request_id / code / state / error 等参数完成使命后就不该继续留在
 * 地址栏：跳转第三方时 `window.location.assign` 会把当前页面 URL 作为 Referer 发出，
 * 浏览器历史也会保留当前条目。在离开确认页前、或进入回调结果页后立即 replaceState
 * 掉查询参数，可同时堵住 Referer 与历史两条泄露路径。无查询时不动，避免无谓改写。
 */
function scrubLocationQuery(): void {
  if (!window.location.search) return
  window.history.replaceState({}, '', window.location.pathname)
}

function scopeMeta(scope: string): { title: string; desc: string } {
  if (scope === 'openid') return { title: '身份标识', desc: '获取你的唯一辰星 ID，用于识别账户身份' }
  if (scope === 'profile') return { title: '基本资料', desc: '查看你的昵称、头像与公开个人信息' }
  if (scope === 'email') return { title: '电子邮箱', desc: '读取与你账号关联的邮箱地址' }
  if (scope === 'offline_access') return { title: '离线访问', desc: '在你离线时刷新访问令牌' }
  return { title: scope, desc: '应用请求的额外权限范围' }
}

export function OAuthAccountPage() {
  const requestId = useRequestId()
  // #330：requestId 变化时以 key 强制重挂载内层组件，pending/message 等请求态
  // 随旧实例一起销毁，杜绝旧请求的同意信息泄露到新请求（consent spoofing）。
  // 重挂载发生在 render 阶段，新请求加载完成前页面不会出现任何旧请求的数据。
  return <OAuthAccountContent key={requestId ?? 'no-request'} requestId={requestId} />
}

function OAuthAccountContent({ requestId }: { requestId: string | null }) {
  const navigate = useNavigate()
  const { user } = useAuth()
  const { pending, message } = usePendingAuthorization(requestId)

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region */}
      <HudPanel className="oauth-card" role="region" aria-label="选择辰星通行证账号">
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
                    <Link to={requestId ? `/login?request_id=${encodeURIComponent(requestId)}` : '/login'} className="flex w-full items-center gap-3.5 border-0 bg-transparent px-4 py-3.5 text-left">
                      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-dashed border-[var(--chenxing-border-strong)] text-[var(--chenxing-muted-foreground)]">+</span>
                      <span className="min-w-0 flex-1">
                        <span className="block text-sm font-medium text-[var(--chenxing-foreground)]">使用其他辰星通行证</span>
                        <span className="block text-[12px] text-[var(--chenxing-muted-foreground)]">登录另一个账号继续授权</span>
                      </span>
                    </Link>
                  </li>
                </ul>
                {/* #240：隐私政策/服务条款尚无链接目标，保留为纯文本，不渲染伪链接 */}
                <p className="oauth-copy is-legal">
                  在使用该应用之前，请知悉「{pending.client_name}」的隐私政策与服务条款。
                </p>
              </>
            ) : null}
          </div>
        </div>
      </HudPanel>
    </OAuthShell>
  )
}

export function OAuthConsentPage() {
  const requestId = useRequestId()
  // #330：与 OAuthAccountPage 同理，requestId 变化时重挂载内层组件，让
  // pending/message/submitting 与进行中的 decide 一并随旧实例销毁；否则旧请求
  // 的同意信息会在新请求加载期间继续展示（consent spoofing），且 A 上的
  // submitting 会永久禁用 B 的按钮。
  return <OAuthConsentContent key={requestId ?? 'no-request'} requestId={requestId} />
}

function OAuthConsentContent({ requestId }: { requestId: string | null }) {
  const { user } = useAuth()
  const { pending, message, setMessage } = usePendingAuthorization(requestId)
  const [submitting, setSubmitting] = useState(false)
  // #406：持有进行中的决策请求；组件卸载时 abort，让 fetch 挂起的 resolve/reject
  // 不再继续执行 scrubLocationQuery / window.location.assign，避免覆盖用户主动
  // 发起的导航，也避免对已卸载组件调用 setMessage / setSubmitting（错误信息丢失）。
  const decideAbortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    return () => { decideAbortRef.current?.abort() }
  }, [])

  async function decide(decision: 'approve' | 'deny') {
    if (!requestId || submitting) return
    setMessage('')
    setSubmitting(true)
    const controller = new AbortController()
    decideAbortRef.current = controller
    try {
      const response = await apiFetch<AuthorizationDecisionResponse>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`, {
        method: 'POST',
        body: JSON.stringify({ decision }),
        signal: controller.signal,
      })
      // 卸载若发生在 fetch resolve 与导航之间，signal 已被 abort，此窗口内必须放弃全部副作用
      if (controller.signal.aborted) return
      const target = safeRedirectTarget(response.redirect_to)
      if (!target) {
        setMessage('授权跳转地址无效，已阻止本次跳转，请重新发起授权。')
        setSubmitting(false)
        return
      }
      // 跳出前先抹掉地址栏与历史中的 request_id（#196），再交给第三方；
      // 顺序不能反：assign 发出的 Referer 与留在历史栈里的条目都取自跳转瞬间的 URL。
      scrubLocationQuery()
      window.location.assign(target)
    } catch (error) {
      if (controller.signal.aborted) return
      setMessage(error instanceof Error ? error.message : '授权请求处理失败。')
      setSubmitting(false)
    }
  }

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region */}
      <HudPanel className="oauth-card" role="region" aria-label="辰星通行证授权确认">
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
            {/* #199：不可伪造身份锚点。redirect_host / client_id 来自服务端校验的
                授权请求与注册数据，应用无法自行伪造；与应用名分层：名称留在标题
                大字号里，身份锚点用等宽小字号 + 「服务端校验」标签独立成组，
                窄屏下 host 可任意断行，不撑破卡片。 */}
            {pending ? (
              <div className="oauth-identity" role="group" aria-label="接入应用身份，由服务端校验">
                <span className="oauth-identity-icon" aria-hidden="true"><Icon name="shield-check" size={15} /></span>
                <span className="oauth-identity-body">
                  <span className="oauth-identity-label">接入域名 · 服务端校验</span>
                  <span className="oauth-identity-host">{pending.redirect_host}</span>
                  <span className="oauth-identity-clientid">Client ID · {pending.client_id}</span>
                </span>
              </div>
            ) : null}
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
                {/* #199：信任提示以不可伪造的接入域名为准，不依赖可自定义的应用名 */}
                <p className="oauth-copy">除非你确认上方接入域名「{pending.redirect_host}」正是你要授权的应用，否则请勿继续授权。应用名称可被自定义，请以服务端校验的接入域名与 Client ID 为准。</p>
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
      </HudPanel>
    </OAuthShell>
  )
}

export function OAuthRedirectPage() {
  // #196：结果分支在清理前固化成状态，进入页面后立即抹掉地址栏、Referer 与历史中的
  // 敏感 query（code/state/error/request_id 等）。读取与清理分离：先读后清，
  // 清理不影响本次渲染要展示的分支，页面展示不再依赖 URL 里的参数。
  const params = new URLSearchParams(window.location.search)
  const [callbackState] = useState(() => {
    const hasError = Boolean(params.get('error')?.trim())
    const hasSuccess = Boolean(params.get('code')?.trim()) && Boolean(params.get('state')?.trim())
    return { hasError, hasSuccess, valid: hasError || hasSuccess }
  })

  // useLayoutEffect 先于绘制执行：避免敏感参数在地址栏闪现一个可被截图/观察的窗口
  useLayoutEffect(() => {
    scrubLocationQuery()
  }, [])

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region。
          保留 aria-live 以便 SPA 内跳转到本页时播报授权结果 */}
      <HudPanel className="oauth-card" role="region" aria-live="polite" aria-label="辰星通行证授权结果">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">{!callbackState.valid ? '授权回调无效' : callbackState.hasError ? '授权未完成' : '授权完成 · 正在返回接入应用'}</span>
        </div>
        <div className="oauth-center">
          <div className="oauth-transfer" aria-hidden="true">
            <span className="oauth-transfer-mark">
              <BrandMark className="h-9 w-9 rounded-[10px] object-contain" />
            </span>
            <span className="oauth-beam" />
            <span className="oauth-transfer-mark is-client">A</span>
          </div>
          {!callbackState.valid ? (
            <>
              <h1 className="oauth-title is-compact">授权回调无效</h1>
              <p className="oauth-copy is-notice">成功回调必须同时包含有效的 code 和 state；错误回调必须包含 error。请重新发起授权。</p>
              <div className="mt-6"><Link to="/console" className="oauth-btn oauth-btn-primary">返回控制台</Link></div>
            </>
          ) : callbackState.hasError ? (
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
      </HudPanel>
    </OAuthShell>
  )
}
