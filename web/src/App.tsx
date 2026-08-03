import type { ReactNode } from 'react'
import { Navigate, usePathname } from './router'
import { AuthProvider, useAuth } from './auth-state'
import { LandingPage } from './pages/landing'
import { AuthPage, BootstrapPage } from './pages/auth'
import { OAuthAccountPage, OAuthConsentPage, OAuthRedirectPage } from './pages/oauth'
import { ConsoleOverview, ConsolePlans, ConsoleProfile, AuthorizedApps } from './pages/console/account'
import { IntegratePage, PlaygroundPage } from './pages/console/developer'
import { AdminAudit, AdminClients, AdminDashboard, AdminUsers, AdminSettings } from './pages/admin'
import { AuthPanel, AuthShell } from './components/shells'
import { Notice } from './components/ui'

function AppContent() {
  const path = usePathname()
  const { status, user, bootstrap } = useAuth()
  const protectedPath = path.startsWith('/console') || path === '/oauth/account' || path === '/oauth/consent'
  const adminPath = path.startsWith('/admin')
  const bootstrapPath = path === '/bootstrap'

  if (bootstrap === 'loading' || (status === 'loading' && (protectedPath || adminPath))) {
    return (
      <AuthShell>
        <AuthPanel>
          <Notice>
            {bootstrap === 'loading' ? '正在检查系统初始化状态，请稍候。' : '正在检查登录状态，请稍候。'}
          </Notice>
        </AuthPanel>
      </AuthShell>
    )
  }

  // Fresh database / no Owner yet: force the first-light bootstrap window.
  if (bootstrap === 'required' && !bootstrapPath) {
    return <Navigate to="/bootstrap" />
  }

  // Owner already exists: bootstrap page becomes a dead end.
  if (bootstrap === 'ready' && bootstrapPath) {
    return <Navigate to="/login" />
  }

  if (protectedPath && status !== 'authenticated') {
    const returnTo = `${window.location.pathname}${window.location.search}`
    return <Navigate to={`/login?returnTo=${encodeURIComponent(returnTo)}`} />
  }
  if (adminPath && status === 'authenticated' && user?.role === 'user') return <Navigate to="/console" />
  const pages: Record<string, ReactNode> = {
    '/': <LandingPage />, '/login': <AuthPage mode="login" />, '/register': <AuthPage mode="register" />,
    '/bootstrap': <BootstrapPage />, '/oauth/account': <OAuthAccountPage />, '/oauth/consent': <OAuthConsentPage />,
    '/oauth/redirect': <OAuthRedirectPage />, '/console': <ConsoleOverview />, '/console/plans': <ConsolePlans />,
    '/console/profile': <ConsoleProfile />, '/console/apps': <AuthorizedApps />, '/console/integrate': <IntegratePage />,
    '/console/playground': <PlaygroundPage />, '/admin': <AdminDashboard />, '/admin/users': <AdminUsers />,
    '/admin/clients': <AdminClients />, '/admin/audit': <AdminAudit />, '/admin/settings': <AdminSettings />,
  }
  return pages[path] ?? <Navigate to="/" />
}

export default function App() {
  return <AuthProvider><AppContent /></AuthProvider>
}
