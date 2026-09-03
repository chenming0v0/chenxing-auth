import { useEffect, useId, useState, type ReactNode } from 'react'
import { Link, NavLink, useLocation } from '../router'
import { useAuth } from '../auth-state'
import { navGroups, pageStatus, type NavGroup } from '../data'
import { BrandLockup, HudPanel, Icon } from '@chenxing/ui'
import { SpaceBackdrop } from '@chenxing/ui'
import { SkipLink, SkipTarget, useModalFocus, useSkipTargetId } from '@chenxing/ui'
import { GlobalTopbar } from './shells-topbar'

/** 角色过滤后的导航分组，是侧栏、底栏和区域面板的唯一数据来源。
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

/** 当前路径所属的分组。底栏只承载这一个分组，分组语义因此不被抹平。
    别名路由（如 /console/security）不在 navGroups 里，按区域落回默认分组。 */
function activeGroup(groups: NavGroup[], pathname: string): NavGroup | undefined {
  const owning = groups.find((group) => group.items.some((item) => item.path === pathname))
  if (owning) return owning
  const fallback = pathname.startsWith('/admin') ? '管理' : '账户'
  return groups.find((group) => group.label === fallback) ?? groups[0]
}

function NavItems({ group }: { group: NavGroup }) {
  return (
    <div>
      <p className="chenxing-nav-label">{group.label}</p>
      {group.items.map((item) => (
        <NavLink key={item.path} to={item.path} className="chenxing-nav-item">
          <Icon name={item.icon} size={16} className="h-4 w-4" />
          {item.label}
        </NavLink>
      ))}
    </div>
  )
}

/** 桌面侧栏导航：按角色过滤后渲染全部分组，active 态由 NavLink 按路径判定。
    移动端不复用它——侧栏在 <1024px 隐藏，导航由底栏 + 区域面板承载。 */
function Sidebar() {
  const groups = useVisibleGroups()
  return (
    <aside className="chenxing-sidebar flex">
      <Link to="/" className="flex items-center gap-3 px-2">
        <BrandLockup subtitle="用户中心" compact />
      </Link>
      <nav className="chenxing-sidebar-scroll mt-5 no-scrollbar" aria-label="控制台导航">
        {groups.map((group) => <NavItems key={group.label} group={group} />)}
      </nav>
    </aside>
  )
}

/** 区域面板：贴底升起的模态列表，按分组标题列出当前角色可见的每一个页面。
    它是移动端的完整导航——底栏放不下的条目不会被静默丢掉，都在这里。
    玻璃容器用 HudPanel，定位与滚动由 app-shell.css 的 .cx-nav-sheet 负责。 */
function NavSheet({ id, groups, onClose }: { id: string; groups: NavGroup[]; onClose: () => void }) {
  const titleId = useId()
  // 库的 useModalFocus 负责初始焦点、Tab 循环、Escape 关闭和焦点归还触发器
  const containerRef = useModalFocus<HTMLElement>(onClose)
  return (
    <div className="cx-nav-sheet-overlay" role="presentation" onClick={onClose}>
      <HudPanel
        ref={containerRef}
        id={id}
        as="section"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="cx-nav-sheet"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start justify-between gap-3">
          <h2 id={titleId} className="chenxing-h2">全部页面</h2>
          <button type="button" className="chenxing-icon-btn" aria-label="关闭" onClick={onClose}>
            <Icon name="x" size={17} />
          </button>
        </div>
        <nav
          className="cx-nav-sheet-scroll no-scrollbar"
          aria-label="全部区域导航"
          /* 点了某一项就算作完成选择。停留在当前页时路径不变，
             不能只靠路径变化关闭面板。 */
          onClick={(event) => {
            if ((event.target as Element).closest('a')) onClose()
          }}
        >
          {groups.map((group) => <NavItems key={group.label} group={group} />)}
        </nav>
      </HudPanel>
    </div>
  )
}

/** 移动端底栏：承载当前分组的全部页面（不再按路径白名单裁剪），条目多于一屏
    时横向滚动；右端常驻的「全部」按钮打开区域面板，跨分组切换走那里。
    桌面端由 CSS 隐藏。 */
function BottomNav() {
  const { pathname } = useLocation()
  const groups = useVisibleGroups()
  const current = activeGroup(groups, pathname)
  const [sheetOpen, setSheetOpen] = useState(false)
  const sheetId = useId()

  // 前进/后退或面板内跳转导致换页后，面板不应留在屏幕上
  useEffect(() => { setSheetOpen(false) }, [pathname])

  return (
    <>
      <nav className="chenxing-bottom-nav" aria-label="当前区域导航">
        <div className="cx-bottom-nav-scroll no-scrollbar">
          {current?.items.map((item) => (
            <NavLink key={item.path} to={item.path} className="chenxing-bottom-tab">
              <Icon name={item.icon} size={18} />
              {item.label}
            </NavLink>
          ))}
        </div>
        <button
          type="button"
          className="chenxing-bottom-tab cx-bottom-more"
          aria-expanded={sheetOpen}
          aria-controls={sheetId}
          aria-haspopup="dialog"
          onClick={() => setSheetOpen((open) => !open)}
        >
          <Icon name="layers" size={18} />
          全部
        </button>
      </nav>
      {sheetOpen ? <NavSheet id={sheetId} groups={groups} onClose={() => setSheetOpen(false)} /> : null}
    </>
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
