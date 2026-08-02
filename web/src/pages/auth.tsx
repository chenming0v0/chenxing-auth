import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from '../router'
import { AuthShell } from '../components/shells'
import { AuthPanel } from '../components/shells'
import { Button, Field, Notice } from '../components/ui'

type AuthMode = 'login' | 'register'

export function AuthPage({ mode }: { mode: AuthMode }) {
  const navigate = useNavigate()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState('')
  const isLogin = mode === 'login'

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!email || !password) { setMessage('请填写邮箱和密码。'); return }
    setMessage(isLogin ? '演示模式：登录接口待接入，已为你保留当前页面。' : '演示模式：注册接口待接入。')
    if (isLogin) window.setTimeout(() => navigate('/console'), 450)
  }

  return <AuthShell action={isLogin ? '创建通行证' : '返回登录'} actionTo={isLogin ? '/register' : '/login'}>
    <AuthPanel>
      <header><span className="eyebrow">{isLogin ? 'SIGN IN · 02' : 'CREATE ID · 03'}</span><h1 className="chenxing-h1">{isLogin ? '欢迎回到辰星' : '创建你的通行证'}</h1><p>{isLogin ? '使用已注册的身份进入辰星认证中枢。' : '从一个安全、清晰的身份开始连接你的应用。'}</p></header>
      {message && <div className="auth-feedback"><Notice tone={message.includes('请') ? 'warning' : 'info'}>{message}</Notice></div>}
      <form className="auth-form" onSubmit={submit}>
        <Field label="邮箱地址" type="email" placeholder="name@example.com" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} />
        <Field label="密码" type="password" placeholder="至少 8 位字符" autoComplete={isLogin ? 'current-password' : 'new-password'} value={password} onChange={(event) => setPassword(event.target.value)} hint={!isLogin ? '请使用大小写字母、数字和符号的组合。' : undefined} />
        {isLogin && <div className="form-options"><label className="check-row"><input type="checkbox" />保持登录</label><Link className="text-link" to="/login">忘记密码？</Link></div>}
        <Button type="submit" icon={isLogin ? 'log-in' : 'rocket'}>{isLogin ? '进入控制台' : '创建通行证'}</Button>
      </form>
      <footer className="auth-footer">{isLogin ? '还没有通行证？' : '已经拥有通行证？'}<Link to={isLogin ? '/register' : '/login'}>{isLogin ? '立即创建' : '前往登录'}</Link></footer>
    </AuthPanel>
  </AuthShell>
}

export function BootstrapPage() {
  const [done, setDone] = useState(false)
  const submit = (event: FormEvent) => { event.preventDefault(); setDone(true) }
  return <AuthShell action="返回登录" actionTo="/login"><AuthPanel>
    <header><span className="eyebrow">SYSTEM BOOTSTRAP · 04</span><h1 className="chenxing-h1">初始化 Owner</h1><p>这是部署后的首次初始化入口。完成后，管理接口将进入受保护状态。</p></header>
    {done ? <Notice tone="success">演示模式：Owner 初始化请求已记录，下一步将由后端完成真实创建。</Notice> : <form className="auth-form" onSubmit={submit}><Field label="Owner 邮箱" type="email" placeholder="owner@example.com" required /><Field label="初始密码" type="password" placeholder="设置高强度密码" required /><Field label="初始化令牌" type="password" placeholder="部署时提供的安全令牌" hint="仅用于首个 Owner 初始化，不会写入日志。" required /><Button type="submit" icon="shield-check">确认初始化</Button></form>}
    <footer className="auth-footer"><Link to="/login">返回统一登录</Link></footer>
  </AuthPanel></AuthShell>
}
