import { useEffect, useState } from 'react'
import { ArrowRight, Check, ExternalLink, ShieldCheck } from 'lucide-react'
import { Link, useLocation, useNavigate } from '../router'
import { useAuth } from '../auth-state'
import { apiFetch, type PendingAuthorization, type AuthorizationDecisionResponse } from '../api'
import { AuthPanel, AuthShell } from '../components/shells'
import { Button, Icon, Notice } from '../components/ui'

function useRequestId(): string | null {
  return new URLSearchParams(useLocation().search).get('request_id')
}

function LoadingState({ message }: { message: string }) {
  return <div className="empty-state"><ShieldCheck size={24} /><strong>{message}</strong></div>
}

export function OAuthAccountPage() {
  const navigate = useNavigate()
  const requestId = useRequestId()
  const { user } = useAuth()
  const [pending, setPending] = useState<PendingAuthorization | null>(null)
  const [message, setMessage] = useState('')
  useEffect(() => {
    if (!requestId) { setMessage('授权请求缺少 request_id，请重新发起。'); return }
    let active = true
    void apiFetch<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`).then((value) => { if (active) setPending(value) }).catch((reason: unknown) => { if (active) setMessage(reason instanceof Error ? reason.message : '授权请求已失效。') })
    return () => { active = false }
  }, [requestId])
  return <AuthShell action="取消" actionTo="/console"><AuthPanel>
    <header><span className="eyebrow">AUTHORIZATION · 05</span><h1 className="chenxing-h1">选择一个账号</h1><p>确认当前浏览器会话是否继续处理此授权请求。</p></header>
    {message && <Notice tone="warning">{message}</Notice>}
    {!message && !pending && <LoadingState message="正在读取授权请求…" />}
    {pending && <><div className="consent-app"><span className="app-mark"><ExternalLink size={23} /></span><div><strong>{pending.client_name}</strong><small>{pending.redirect_host}</small></div><span className="chenxing-badge-success">服务端已校验</span></div><div className="list-stack"><button className="account-choice" onClick={() => navigate(`/oauth/consent?request_id=${encodeURIComponent(pending.request_id)}`)}><span className="avatar-button">{(user?.display_name || user?.username || '辰').slice(0, 1)}</span><span><strong>{user?.display_name || user?.username}</strong><small>{user?.email}</small></span><ArrowRight size={17} /></button><Link className="account-choice" to="/login"><span className="account-add"><Icon name="user" size={17} /></span><span><strong>使用其他账号</strong><small>退出当前会话并使用其他身份</small></span><ArrowRight size={17} /></Link></div></>}
    <footer className="auth-footer"><ShieldCheck size={14} />授权请求由当前 Session 绑定</footer>
  </AuthPanel></AuthShell>
}

export function OAuthConsentPage() {
  const requestId = useRequestId()
  const [pending, setPending] = useState<PendingAuthorization | null>(null)
  const [message, setMessage] = useState('')
  const [submitting, setSubmitting] = useState(false)
  useEffect(() => {
    if (!requestId) { setMessage('授权请求缺少 request_id，请重新发起。'); return }
    let active = true
    void apiFetch<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`).then((value) => { if (active) setPending(value) }).catch((reason: unknown) => { if (active) setMessage(reason instanceof Error ? reason.message : '授权请求已失效。') })
    return () => { active = false }
  }, [requestId])

  async function decide(decision: 'approve' | 'deny') {
    if (!requestId || submitting) return
    setMessage('')
    setSubmitting(true)
    try {
      const response = await apiFetch<AuthorizationDecisionResponse>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(requestId)}`, { method: 'POST', body: JSON.stringify({ decision }) })
      // The redirect URI and state were validated by the backend. Do not render its query,
      // because an approval redirect contains a one-time authorization code.
      window.location.assign(response.redirect_to)
    } catch (error) {
      setMessage(error instanceof Error ? error.message : '授权请求处理失败。')
      setSubmitting(false)
    }
  }

  return <AuthShell action="取消" actionTo="/console"><AuthPanel className="consent-panel">
    <header><span className="eyebrow">CONSENT · 06</span><h1 className="chenxing-h1">授权应用访问</h1><p>只展示后端返回的应用信息和权限范围。</p></header>
    {message && <div className="auth-feedback"><Notice tone="warning">{message}</Notice></div>}
    {!message && !pending && <LoadingState message="正在读取授权摘要…" />}
    {pending && <><div className="consent-app"><span className="app-mark"><ExternalLink size={23} /></span><div><strong>{pending.client_name}</strong><small>{pending.redirect_host}</small></div><span className="chenxing-badge-success">已验证</span></div><div className="consent-scopes"><span className="chenxing-label">请求的权限</span>{pending.scopes.map((scope) => <div className="scope-row" key={scope}><Check size={15} />{scope}</div>)}</div><Notice tone="info">本次请求将在 {pending.expires_in} 秒内失效，且只绑定当前 Session。</Notice><div className="panel-actions consent-actions"><Button onClick={() => void decide('approve')} icon="check" disabled={submitting}>允许访问</Button><Button variant="ghost" onClick={() => void decide('deny')} icon="x" disabled={submitting}>拒绝</Button></div><p className="consent-footnote">批准或拒绝后，页面只跳转到后端返回的已校验地址。</p></>}
  </AuthPanel></AuthShell>
}

export function OAuthRedirectPage() {
  const query = new URLSearchParams(useLocation().search)
  const hasError = query.has('error')
  return <AuthShell><AuthPanel className="redirect-panel"><div className="redirect-icon"><ShieldCheck size={34} /></div><span className="eyebrow">AUTHORIZATION · 07</span><h1 className="chenxing-h1">OAuth 回调已收到</h1><p>{hasError ? '授权请求被拒绝或未完成，请返回发起方重试。' : '回调参数已交给发起方处理，辰星不会在此页面展示授权码或 Token。'}</p>{hasError ? <Notice tone="warning">授权没有完成。</Notice> : <Notice tone="success">处理完成。</Notice>}<Link className="auth-footer" to="/console">返回控制台</Link></AuthPanel></AuthShell>
}
