import { useState } from 'react'
import { Link, useNavigate } from '../router'
import { ArrowRight, Check, ExternalLink, ShieldCheck } from 'lucide-react'
import { AuthPanel, AuthShell } from '../components/shells'
import { Button, Icon, Notice } from '../components/ui'

export function OAuthAccountPage() {
  const navigate = useNavigate()
  return <AuthShell action="取消" actionTo="/login"><AuthPanel>
    <header><span className="eyebrow">AUTHORIZATION · 05</span><h1 className="chenxing-h1">选择一个账号</h1><p>星图工作台正在请求使用辰星通行证继续。</p></header>
    <div className="list-stack"><button className="account-choice" onClick={() => navigate('/oauth/consent')}><span className="avatar-button">辰</span><span><strong>林默</strong><small>lin.mo@example.com</small></span><ArrowRight size={17} /></button><button className="account-choice" onClick={() => navigate('/login')}><span className="account-add"><Icon name="user" size={17} /></span><span><strong>使用其他账号</strong><small>切换到另一个辰星身份</small></span><ArrowRight size={17} /></button></div>
    <footer className="auth-footer"><ShieldCheck size={14} />你的账号信息受辰星安全策略保护</footer>
  </AuthPanel></AuthShell>
}

export function OAuthConsentPage() {
  const navigate = useNavigate()
  const [decision, setDecision] = useState<'idle' | 'denied'>('idle')
  return <AuthShell action="取消" actionTo="/login"><AuthPanel className="consent-panel">
    <header><span className="eyebrow">CONSENT · 06</span><h1 className="chenxing-h1">授权应用访问</h1><p>请确认你了解这个应用将会读取的信息。</p></header>
    <div className="consent-app"><span className="app-mark"><ExternalLink size={23} /></span><div><strong>星图工作台</strong><small>xingtu.example.com</small></div><span className="chenxing-badge-success">已验证</span></div>
    <div className="consent-scopes"><span className="chenxing-label">请求的权限</span><div className="scope-row"><Check size={15} />读取你的基本资料</div><div className="scope-row"><Check size={15} />读取你的邮箱地址</div><div className="scope-row"><Check size={15} />创建和管理登录会话</div></div>
    {decision === 'denied' && <div className="auth-feedback"><Notice tone="warning">你已拒绝授权。可以返回登录页重新开始。</Notice></div>}
    <div className="panel-actions consent-actions"><Button onClick={() => navigate('/oauth/redirect')} icon="check">允许访问</Button><Button variant="ghost" onClick={() => setDecision('denied')} icon="x">拒绝</Button></div>
    <p className="consent-footnote">授权后，你可以随时在「已授权应用」中撤销访问。</p>
  </AuthPanel></AuthShell>
}

export function OAuthRedirectPage() {
  const [ready, setReady] = useState(false)
  return <AuthShell><AuthPanel className="redirect-panel"><div className="redirect-icon"><ShieldCheck size={34} /></div><span className="eyebrow">AUTHORIZATION · 07</span><h1 className="chenxing-h1">正在返回星图工作台</h1><p>授权状态已确认，正在安全地传递一次性授权码。</p><div className="redirect-loader"><span /><span /><span /></div>{ready ? <Notice tone="success">演示模式：重定向接口待接入。</Notice> : <Button variant="ghost" icon="arrow-right" onClick={() => setReady(true)}>查看跳转状态</Button>}<Link className="auth-footer" to="/console">返回控制台</Link></AuthPanel></AuthShell>
}
