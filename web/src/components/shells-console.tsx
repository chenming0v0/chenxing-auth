import type { ReactNode } from 'react'
import { Link, useLocation } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus, type NavGroup } from '../data'
import { BrandLockup, SideNav, SpaceBackdrop, type SideNavGroup, type SideNavLinkProps } from '@chenxing/ui'
import { SkipLink, SkipTarget, useSkipTargetId } from '@chenxing/ui'
import { GlobalTopbar } from './shells-topbar'

/** 角色过滤后的导航分组，是 SideNav（侧栏、底栏和「全部」面板）的唯一数据来源。
    管理/系统分组只对已登录的管理角色显示（user 为 null 时必须显式排除，
    user?.role !== 'user' 在 null 时恒真）；ownerOnly 条目只对 owner 显示；
    过滤后为空的分组整组丢弃，避免出现只有标题没有条目的空分组。 */
function useVisibleGroups(): NavGroup[] {
  const { user } = useAuth()
  const showAdmin = user != null && user.role !== 'user'
  return navGroups
    .filter((group) => group.label === '账户' || group.label === '开发者' || showAdmin)
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => !item.ownerOnly || user?.role === 'owner'),
    }))
    .filter((group) => group.items.length > 0)
}

/** 库 SideNav 的链接走项目 Link：SPA 导航 + 未保存草稿守卫，而不是整页刷新 */
function renderNavLink({ href, ...props }: SideNavLinkProps) {
  return <Link to={href} {...props} />
}

/** 业务侧导航：只负责按角色过滤数据与接入路由，桌面侧栏 / 移动端底栏 /
    「全部」面板的结构、断点与可访问性都由 @chenxing/ui 的 SideNav 负责。 */
function ConsoleNav({ pathname }: { pathname: string }) {
  const groups = useVisibleGroups()
  const sideGroups: SideNavGroup[] = groups.map((group) => ({
    label: group.label,
    items: group.items.map((item) => ({ label: item.label, href: item.path, icon: item.icon })),
  }))
  return (
    <SideNav
      groups={sideGroups}
      currentPath={pathname}
      /* 别名路由（如 /console/security）不在 navGroups 里，按区域落回默认分组 */
      fallbackGroup={pathname.startsWith('/admin') ? '管理' : '账户'}
      brand={<Link to="/" className="flex items-center gap-3"><BrandLockup subtitle="用户中心" compact /></Link>}
      renderLink={renderNavLink}
    />
  )
}

/**
 * 控制台布局。subnav 是页面的二级分栏（TopbarSubnav）：挂在顶栏主胶囊下方，
 * 内容区按分栏高度下移，避免置顶时第二枚胶囊压住页头。
 */
export function ConsoleLayout({ children, subnav }: { children: ReactNode; subnav?: ReactNode }) {
  const location = useLocation()
  const status = pageStatus[location.pathname] || (location.pathname.startsWith('/admin') ? '管理' : '控制台')
  /* 跳过链接盖在最前（侧栏/顶栏之上），内容锚点放在内容列起点，
     这样跳过链接一次 Tab 就能越过侧栏、顶栏与汉堡菜单直达页面内容 */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className="console-shell" opacity={0.4} dense>
      <SkipLink targetId={targetId} />
      <ConsoleNav pathname={location.pathname} />
      <div className="chenxing-sidenav-main relative z-[var(--chenxing-z-content)] flex min-h-screen flex-col">
        {/* sidebar already carries the brand lockup, so the topbar brand only
            appears once the bar condenses into its capsule
            所有区域入口（控制台/开发者/管理）都在 NavMenu 本体里，无需 menuExtra */}
        <GlobalTopbar status={status} hideBrandWhenExpanded subnav={subnav} />
        <div className={`chenxing-console-content flex-1 px-4 py-6 pb-10 sm:px-6 lg:px-8${subnav ? ' has-subnav' : ''}`}>
          <SkipTarget targetId={targetId} />
          {children}
        </div>
      </div>
    </SpaceBackdrop>
  )
}
