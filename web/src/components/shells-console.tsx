import type { ReactNode } from 'react'
import { Link, NavLink, useLocation } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus } from '../data'
import { BrandLockup, Icon } from './ui'
import { SpaceBackdrop } from './space'
import { SkipLink, SkipTarget, useSkipTargetId } from './skip-link'
import { GlobalTopbar } from './shells-topbar'

/** 桌面侧栏导航分组：按角色过滤可见分组，渲染带 active 态的导航项。
    移动端不再复用它——汉堡菜单只保留区域级入口（控制台/开发者/管理），
    区域内页面切换由底栏承载。 */
function ConsoleNavGroups() {
  const { user } = useAuth()
  const location = useLocation()
  /* 管理/系统分组只对已登录的管理角色显示；user 为 null 时必须显式排除，
     与 NavMenu 的 showAdmin 判定保持一致（user?.role !== 'user' 在 null 时恒真） */
  const showAdmin = user != null && user.role !== 'user'
  const visible = navGroups.filter(
    (group) => group.label === '账户' || group.label === '开发者' || showAdmin,
  )
  return (
    <>
      {visible.map((group) => (
        <div key={group.label}>
          <p className="chenxing-nav-label">{group.label}</p>
          {group.items.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className="chenxing-nav-item"
              aria-current={location.pathname === item.path ? 'page' : undefined}
            >
              <Icon name={item.icon} size={16} className="h-4 w-4" />
              {item.label}
            </NavLink>
          ))}
        </div>
      ))}
    </>
  )
}

function Sidebar() {
  return (
    <aside className="chenxing-sidebar flex">
      <Link to="/" className="flex items-center gap-3 px-2">
        <BrandLockup subtitle="用户中心" compact />
      </Link>
      <nav className="chenxing-sidebar-scroll mt-5 no-scrollbar" aria-label="控制台导航">
        <ConsoleNavGroups />
      </nav>
    </aside>
  )
}

/** 移动端底栏按当前区域切换：账户区显示「总览 / 个人信息 / 已授权应用」，
    开发者区显示「接入应用 / 授权测试 / 套餐与权益」，管理区（/admin*）显示
    管理与系统分组的四项；桌面端由 CSS 隐藏。 */
function BottomNav() {
  const location = useLocation()
  const groupItems = (label: string) => navGroups.find((group) => group.label === label)?.items ?? []
  const developer = groupItems('开发者')
  const core = location.pathname.startsWith('/admin')
    ? [...groupItems('管理'), ...groupItems('系统')]
    : developer.some((item) => item.path === location.pathname)
      ? developer
      : groupItems('账户')
  return (
    <nav className="chenxing-bottom-nav" aria-label="控制台快捷导航">
      {core.map((item) => (
        <NavLink
          key={item.path}
          to={item.path}
          className="chenxing-bottom-tab"
          aria-current={location.pathname === item.path ? 'page' : undefined}
        >
          <Icon name={item.icon} size={18} />
          {item.label}
        </NavLink>
      ))}
    </nav>
  )
}

export function ConsoleLayout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const status = pageStatus[location.pathname] || (location.pathname.startsWith('/admin') ? '管理' : '控制台')
  /* 跳过链接盖在最前（侧栏/顶栏之上），内容锚点放在内容列起点，
     这样跳过链接一次 Tab 就能越过侧栏、顶栏与汉堡菜单直达页面内容 */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className="console-shell" opacity={0.4} dense>
      <SkipLink targetId={targetId} />
      <Sidebar />
      <div className="chenxing-console-main relative z-[var(--chenxing-z-content)] flex min-h-screen flex-col">
        {/* sidebar already carries the brand lockup, so the topbar brand only
            appears once the bar condenses into its capsule
            所有区域入口（控制台/开发者/管理）都在 NavMenu 本体里，无需 menuExtra */}
        <GlobalTopbar status={status} hideBrandWhenExpanded />
        <div className="chenxing-console-content flex-1 px-4 py-6 pb-10 sm:px-6 lg:px-8">
          <SkipTarget targetId={targetId} />
          {children}
        </div>
      </div>
      <BottomNav />
    </SpaceBackdrop>
  )
}
