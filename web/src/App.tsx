import { useEffect, type ReactNode } from 'react'
import { Navigate, usePathname } from './router'
import { loginRecoveryTarget } from './api'
import { AuthProvider, useAuth } from './auth-state'
import { getDocumentTitle } from './data'
import { LandingPage } from './pages/landing'
import { AuthPage, BootstrapPage } from './pages/auth'
import { OAuthAccountPage, OAuthConsentPage, OAuthRedirectPage } from './pages/oauth'
import { ConsoleOverview, ConsolePlans, ConsoleProfile, ConsoleSecurity, AuthorizedApps, SecurityLogsPage } from './pages/console/account'
import { IntegratePage, PlaygroundPage } from './pages/console/developer'
import { AdminAudit, AdminClients, AdminDashboard, AdminPlans, AdminUsers, AdminSettings } from './pages/admin'
import { AuthPanel, AuthShell } from './components/shells'
import { Button, Notice } from './components/ui'

function AppContent() {
  const path = usePathname()
  const { status, user, bootstrap, refresh, refreshBootstrap } = useAuth()

  useEffect(() => {
    document.title = getDocumentTitle(path)
  }, [path])

  const protectedPath = path.startsWith('/console') || path === '/settings/security' || path === '/oauth/account' || path === '/oauth/consent'
  const adminPath = path.startsWith('/admin')
  const bootstrapPath = path === '/bootstrap'

  if (bootstrap === 'loading' || (status === 'loading' && (protectedPath || adminPath))) {
    return (
      <AuthShell status={bootstrap === 'loading' ? '检查系统状态' : '校验会话'}>
        <AuthPanel>
          <Notice tone="info">
            {bootstrap === 'loading' ? '正在检查系统初始化状态，请稍候。' : '正在检查登录状态，请稍候。'}
          </Notice>
        </AuthPanel>
      </AuthShell>
    )
  }

  // 瞬态故障（网络错误 / 5xx）后初始化状态未知：不渲染任何页面，提供重试。
  // 不能在此处回退到 ready——未初始化系统会被踢到 /login，而登录又被后端拒绝。
  if (bootstrap === 'error') {
    return (
      <AuthShell status="系统状态检查失败">
        <AuthPanel>
          <div className="space-y-4">
            <Notice tone="warning">暂时无法确认系统初始化状态，请检查后端服务或网络连接后重试。</Notice>
            <Button type="button" icon="refresh-cw" className="w-full" onClick={() => void refreshBootstrap()}>
              重新检查系统状态
            </Button>
          </div>
        </AuthPanel>
      </AuthShell>
    )
  }

  if (status === 'error' && (protectedPath || adminPath)) {
    return (
      <AuthShell status="会话检查失败">
        <AuthPanel>
          <div className="space-y-4">
            <Notice tone="warning">暂时无法确认登录状态，请检查后端服务或网络连接后重试。</Notice>
            <Button type="button" icon="refresh-cw" className="w-full" onClick={() => void refresh()}>
              重新检查登录状态
            </Button>
          </div>
        </AuthPanel>
      </AuthShell>
    )
  }

  // Fresh database / no Owner yet: force the first-light bootstrap window.
  if (bootstrap === 'required' && !bootstrapPath) {
    return <Navigate replace to="/bootstrap" />
  }

  // Owner already exists: bootstrap page becomes a dead end.
  if (bootstrap === 'ready' && bootstrapPath) {
    return <Navigate replace to="/login" />
  }

  // 未认证用户一律不得进入受保护路径，包括管理后台（#327）：
  // 此前 /admin/* 不在拦截范围，未登录直接访问会渲染管理页 UI 骨架，
  // 泄露页面结构与菜单，尽管 API 请求本身会 401。
  if ((protectedPath || adminPath) && status !== 'authenticated') {
    // loginRecoveryTarget 会把 OAuth 的 request_id 提到顶层查询参数（#270）：
    // 登录页只读自己的 request_id 决定登录后是否重新绑定待授权请求，
    // 埋在 returnTo 里读不到，用户会在登录页与确认页之间反复跳转。
    return <Navigate replace to={loginRecoveryTarget(window.location.pathname, window.location.search)} />
  }

  // 已认证的普通用户无权进入管理后台，送回用户控制台。
  if (adminPath && status === 'authenticated' && user?.role === 'user') {
    return <Navigate replace to="/console" />
  }

  const pages: Record<string, ReactNode> = {
    '/': <LandingPage />,
    '/login': <AuthPage key="login" mode="login" />,
    '/register': <AuthPage key="register" mode="register" />,
    '/bootstrap': <BootstrapPage />,
    '/oauth/account': <OAuthAccountPage />,
    '/oauth/consent': <OAuthConsentPage />,
    '/oauth/redirect': <OAuthRedirectPage />,
    '/console': <ConsoleOverview />,
    '/console/plans': <ConsolePlans />,
    '/console/profile': <ConsoleProfile />,
    '/console/security': <ConsoleSecurity />,
    '/settings/security': <ConsoleSecurity />,
    '/console/apps': <AuthorizedApps />,
    '/console/logs': <SecurityLogsPage />,
    '/console/integrate': <IntegratePage />,
    '/console/playground': <PlaygroundPage />,
    '/admin': <AdminDashboard />,
    '/admin/users': <AdminUsers />,
    '/admin/plans': <AdminPlans />,
    '/admin/clients': <AdminClients />,
    '/admin/audit': <AdminAudit />,
    '/admin/settings': <AdminSettings />,
  }

  return pages[path] ?? <Navigate replace to="/" />
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}
