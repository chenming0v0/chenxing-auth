import type { ReactNode } from 'react'
import { Navigate, usePathname } from './router'
import { LandingPage } from './pages/landing'
import { AuthPage, BootstrapPage } from './pages/auth'
import { OAuthAccountPage, OAuthConsentPage, OAuthRedirectPage } from './pages/oauth'
import { ConsoleOverview, ConsolePlans, ConsoleProfile, AuthorizedApps } from './pages/console/account'
import { IntegratePage, PlaygroundPage } from './pages/console/developer'
import { AdminDashboard, AdminUsers, AdminSettings } from './pages/admin'

export default function App() {
  const path = usePathname()
  const pages: Record<string, ReactNode> = {
    '/': <LandingPage />, '/login': <AuthPage mode="login" />, '/register': <AuthPage mode="register" />,
    '/bootstrap': <BootstrapPage />, '/oauth/account': <OAuthAccountPage />, '/oauth/consent': <OAuthConsentPage />,
    '/oauth/redirect': <OAuthRedirectPage />, '/console': <ConsoleOverview />, '/console/plans': <ConsolePlans />,
    '/console/profile': <ConsoleProfile />, '/console/apps': <AuthorizedApps />, '/console/integrate': <IntegratePage />,
    '/console/playground': <PlaygroundPage />, '/admin': <AdminDashboard />, '/admin/users': <AdminUsers />,
    '/admin/settings': <AdminSettings />,
  }
  return pages[path] ?? <Navigate to="/" />
}
