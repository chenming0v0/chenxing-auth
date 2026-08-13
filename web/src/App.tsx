import { useEffect, type ReactNode } from 'react'
import { Navigate, usePathname } from './router'
import { loginRecoveryTarget } from './api'
import { AuthProvider, useAuth } from './auth-state'
import { getDocumentTitle } from './data'
import { LandingPage } from './pages/landing'
import { AuthPage, BootstrapPage } from './pages/auth'
import { OAuthAccountPage, OAuthConsentPage, OAuthRedirectPage } from './pages/oauth'
import { ConsoleOverview, ConsolePlans, ConsoleProfile, AuthorizedApps, SecurityLogsPage } from './pages/console/account'
import { IntegratePage, PlaygroundPage } from './pages/console/developer'
import { AdminAudit, AdminClients, AdminDashboard, AdminPlans, AdminUsers, AdminSettings } from './pages/admin'
import { AuthPanel, AuthShell } from './components/shells'
import { Button, Notice } from './components/ui'

function AppContent() {
  const path = usePathname()
  const { status, user, bootstrap, refresh } = useAuth()

  useEffect(() => {
    document.title = getDocumentTitle(path)
  }, [path])

  const protectedPath = path.startsWith('/console') || path === '/oauth/account' || path === '/oauth/consent'
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
    return <Navigate to="/bootstrap" replace />
  }

  // Owner already exists: bootstrap page becomes a dead end.
  if (bootstrap === 'ready' && bootstrapPath) {
    return <Navigate to="/login" replace />
  }

  if (protectedPath && status !== 'authenticated') {
    // loginRecoveryTarget 会把 OAuth 的 request_id 提到顶层查询参数（#270）：
    // 登录页只读自己的 request_id 决定登录后是否重新绑定待授权请求，
    // 埋在 returnTo 里读不到，用户会在登录页与确认页之间反复跳转。
    return <Navigate to={loginRecoveryTarget(window.location.pathname, window.location.search)} replace />
  }

  if (adminPath && status === 'authenticated' && user?.role === 'user') {
    return <Navigate to="/console" replace />
  }

  const pages: Record<string, ReactNode> = {
    '/': <LandingPage />,
    '/login': <AuthPage mode="login" />,
    '/register': <AuthPage mode="register" />,
    '/bootstrap': <BootstrapPage />,
    '/oauth/account': <OAuthAccountPage />,
    '/oauth/consent': <OAuthConsentPage />,
    '/oauth/redirect': <OAuthRedirectPage />,
    '/console': <ConsoleOverview />,
    '/console/plans': <ConsolePlans />,
    '/console/profile': <ConsoleProfile />,
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

  return pages[path] ?? <Navigate to="/" replace />
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  )
}
