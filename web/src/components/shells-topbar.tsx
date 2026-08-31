import { useEffect, useState, type CSSProperties, type ReactNode } from 'react'
import {
  AvatarContent,
  BrandMark,
  Icon,
  Topbar,
  TopbarAccountPanel,
  TopbarQuotaCard,
} from '@chenxing/ui'
import { Link, prepareNavigation } from '../router'
import { useAuth } from '../auth-state'
import { avatarUrl, getEntitlements, type EntitlementItem } from '../api'

/* 汉堡菜单内容：认证平台的主导航。行样式沿用组件库抽屉的 cx-nav-row 体系，
   路由跳转必须走项目 Link（SPA 导航 + 草稿守卫），因此不用库的 TopbarNavRow
   （它渲染裸 <a href>，整页刷新）。点击关闭由库 Topbar 的面板级
   closest('a, button') 委托处理，这里不再传关闭回调。 */
function NavMenuContent({ extra }: { extra?: ReactNode }) {
  /* 管理入口只对已登录的管理角色显示；未登录时 user 为 null，必须显式排除 */
  const { user } = useAuth()
  const showAdmin = user != null && user.role !== 'user'
  return (
    <>
      <Link to="/" className="cx-nav-row" style={{ '--i': 0 } as CSSProperties}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">主页</span></span>
        <Icon name="arrow-up-right" size={16} />
      </Link>
      <Link to="/console" className="cx-nav-row" style={{ '--i': 1 } as CSSProperties}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">控制台</span></span>
        <Icon name="layout-dashboard" size={16} />
      </Link>
      {/* 开发者入口默认落在「接入应用」：开发者分组的第一页 */}
      <Link to="/console/integrate" className="cx-nav-row" style={{ '--i': 2 } as CSSProperties}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">开发者</span></span>
        <Icon name="code-2" size={16} />
      </Link>
      {/* 管理入口默认落在「仪表盘」：管理分组的第一页，具体页面切换交给管理区底栏 */}
      {showAdmin ? (
        <Link to="/admin" className="cx-nav-row" style={{ '--i': 3 } as CSSProperties}>
          <span className="cx-nav-row-label"><span className="cx-nav-row-text">管理</span></span>
          <Icon name="gauge" size={16} />
        </Link>
      ) : null}
      <span className="cx-nav-row is-static" style={{ '--i': showAdmin ? 4 : 3 } as CSSProperties}>
        <span className="cx-nav-row-label"><span className="cx-nav-row-text">应用广场</span>
          <span className="chenxing-caption ml-2 self-center text-[10px] uppercase tracking-[0.08em] text-[var(--chenxing-muted-foreground)]">即将上线</span>
        </span>
        <Icon name="store" size={16} />
      </span>
      {extra ? <div className="cx-nav-panel-extra">{extra}</div> : null}
    </>
  )
}

/* #692 侧缓解：账户面板里的名称与 handle 是用户可控的长文本
   （`display_name` 最长 128、`username` 最长 64）。库的 TopbarAccountPanel
   把 name/meta.value 当作 ReactNode 插槽渲染，容器（.cx-account-header 与
   两列 meta 网格）没有断行或 min-width:0 约束，连续无空格的长串会按
   max-content 撑宽，被胶囊抽屉的 overflow:hidden 裁掉。
   这里在本仓库能控制的插槽内侧包一层受控宽度 + 任意断行的块，让长串在面板
   宽度内折行。这是缓解不是根治：根治要在组件库给
   .cx-account-header 的名称行和 meta 单元格补上断行/收缩约束，
   否则任何调用方传裸字符串仍会溢出。 */
function WrapLong({ children }: { children: ReactNode }) {
  return <span className="block max-w-full [overflow-wrap:anywhere]">{children}</span>
}

/* 账户面板：库 Topbar 只在面板打开（含退出动画窗口）期间挂载它，
   所以配额请求挂在 mount 上等价于「打开时加载」。
   竞态与 stale 防护（#386）：cancelled 守卫让卸载后 in-flight 回调作废；
   面板卸载即销毁本地状态，下次打开重新加载，不会闪现旧配额。 */
function AccountPanel() {
  const { user, logout } = useAuth()
  const [entitlements, setEntitlements] = useState<{ daily: EntitlementItem | null; monthly: EntitlementItem | null } | null>(null)

  useEffect(() => {
    let cancelled = false
    void getEntitlements()
      .then((data) => {
        if (cancelled) return
        const daily = data.entitlements.find((item) => item.key === 'daily_auth') ?? null
        const monthly = data.entitlements.find((item) => item.key === 'monthly_auth') ?? null
        setEntitlements({ daily, monthly })
      })
      .catch(() => {
        if (cancelled) return
        setEntitlements({ daily: null, monthly: null })
      })
    return () => { cancelled = true }
  }, [user?.id])

  const name = user?.display_name || user?.username || '辰'
  const memberId = user?.id != null ? `NO.${String(user.id).padStart(6, '0')}` : 'NO.000000'
  const handle = user?.username ? `@${user.username}` : '@user'

  return (
    <TopbarAccountPanel
      avatar={<AvatarContent src={avatarUrl(user)} name={name} />}
      name={<WrapLong>{name}</WrapLong>}
      meta={[
        { label: '会员序列', value: memberId },
        { label: '@ Handle', value: <WrapLong>{handle}</WrapLong>, accent: true },
      ]}
      extra={entitlements && (entitlements.daily || entitlements.monthly) ? (
        <>
          {entitlements.daily ? (
            <TopbarQuotaCard
              label="每日授权调用"
              value={`${entitlements.daily.used} / ${typeof entitlements.daily.limit === 'number' ? entitlements.daily.limit : '∞'}`}
            />
          ) : null}
          {entitlements.monthly ? (
            <TopbarQuotaCard
              label="每月授权调用"
              value={`${entitlements.monthly.used} / ${typeof entitlements.monthly.limit === 'number' ? entitlements.monthly.limit : '∞'}`}
            />
          ) : null}
        </>
      ) : null}
    >
      <Link to="/console/profile" className="chenxing-menu-item">
        <Icon name="user" className="text-[var(--chenxing-cyan)]" size={16} />账户设置
      </Link>
      <Link to="/console/plans" className="chenxing-menu-item">
        <Icon name="receipt" className="text-[var(--chenxing-cyan)]" size={16} />套餐订阅
      </Link>
      <span className="chenxing-menu-item is-static">
        <Icon name="book-open" className="text-[var(--chenxing-cyan)]" size={16} />文档中心
        <span className="ml-auto chenxing-caption text-[10px] uppercase tracking-[0.08em] text-[var(--chenxing-muted-foreground)]">即将上线</span>
      </span>
      <div className="chenxing-divider my-1" />
      <button
        type="button"
        className="chenxing-menu-item"
        onClick={(event) => {
          // 先取得一次性导航意图。草稿守卫拒绝时既不撤销会话也不关闭菜单：
          // stopPropagation 阻止库面板的「点按钮即关闭」委托触发（#530）。
          const intent = prepareNavigation('/login')
          if (!intent) {
            event.stopPropagation()
            return
          }
          // logout 永不 reject（#325）：成功与失败都跳登录页，跳转行为一致；
          // 撤销失败时带 logout=failed 标记，登录页据此提示「未能完全登出」。
          void logout().then(
            ({ revoked }) => { intent.commit(revoked ? '/login' : '/login?logout=failed') },
            () => { intent.commit('/login?logout=failed') },
          )
        }}
      >
        <Icon name="log-out" className="text-[var(--chenxing-error)]" size={16} />退出
      </button>
    </TopbarAccountPanel>
  )
}

/* 全局顶栏：库 Topbar 的业务适配层。品牌、状态、导航菜单、账户面板与登录 CTA
   全部通过插槽注入；胶囊/抽屉/遮罩的结构、可访问性与动效编排由库负责。 */
export function GlobalTopbar({
  status,
  action,
  actionTo,
  menuExtra,
  links,
  hideBrandWhenExpanded = false,
}: {
  status: ReactNode
  action?: string
  actionTo?: string
  menuExtra?: ReactNode
  /** 桌面端内联锚点导航：只在页面顶部（顶栏全宽展开态）显示，
      收拢成胶囊后隐去，导航职责交还汉堡菜单。 */
  links?: readonly { label: string; href: string }[]
  hideBrandWhenExpanded?: boolean
}) {
  const { status: authStatus, user } = useAuth()
  const loggedIn = authStatus === 'authenticated'
  const name = user?.display_name || user?.username || '辰'

  return (
    <Topbar
      /* 只留字形：50px 行高里放不下两行中文，且首页 hero、控制台侧栏、
         登录面板都已各自承载完整品牌名，顶栏重复一遍只是挤占密度。 */
      brand={
        <Link to="/" aria-label="返回首页">
          <BrandMark className="chenxing-topbar-mark" />
        </Link>
      }
      status={status}
      links={links}
      hideBrandWhenExpanded={hideBrandWhenExpanded}
      menu={<NavMenuContent extra={menuExtra} />}
      account={loggedIn ? {
        trigger: <AvatarContent src={avatarUrl(user)} name={name} />,
        label: '账户菜单',
        panel: <AccountPanel />,
      } : undefined}
      actions={!loggedIn && action && actionTo ? (
        <Link to={actionTo} className="chenxing-topbar-cta">{action}</Link>
      ) : undefined}
    />
  )
}
