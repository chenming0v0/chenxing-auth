import { useCallback, useEffect, useState, type ReactNode } from 'react'
import { Link, prepareNavigation } from '../router'
import { useAuth } from '../auth-state'
import { avatarUrl, getEntitlements, type EntitlementItem } from '../api'
import { AvatarContent, BrandMark, Icon } from './ui'
import { ScrambleText } from './motion'
import {
  NavMenu,
  useAccordionHeight,
  useExitDelay,
  useNavDisclosure,
  useTopbarExpanded,
} from './shells-nav'

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
  const { expanded, sentinelRef } = useTopbarExpanded()
  const { status: authStatus, user, logout } = useAuth()
  const loggedIn = authStatus === 'authenticated'

  /* 汉堡菜单与账户菜单共享抽屉：两个按钮互斥，点击任一个都会在胶囊内展开抽屉 */
  const nav = useNavDisclosure()
  const account = useNavDisclosure()

  /* 配额数据：仅在账户菜单打开时加载。
     竞态与 stale 防护（#386）：
     - 每次 effect 运行持有独立的 cancelled 守卫，关闭/重开时上一轮 in-flight
       回调（成功与失败分支）作废，旧响应不能覆盖新一轮状态——最新请求胜出；
     - 关闭菜单即清空 entitlements，下次打开先渲染空态，不再闪现上一轮的旧配额。 */
  const [entitlements, setEntitlements] = useState<{ daily: EntitlementItem | null; monthly: EntitlementItem | null } | null>(null)

  useEffect(() => {
    if (!account.open) {
      setEntitlements(null)
      return
    }
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
  }, [account.open, user?.id])

  // 点击头像时：关闭汉堡菜单，打开账户抽屉
  const toggleAccount = useCallback(() => {
    if (nav.open) nav.close()
    account.toggle()
  }, [nav, account])

  // 点击汉堡时：关闭账户菜单，打开汉堡抽屉
  const toggleNav = useCallback(() => {
    if (account.open) account.close()
    nav.toggle()
  }, [nav, account])

  const anyOpen = nav.open || account.open
  /* 450ms = 抽屉收拢 0.45s（遮罩淡出 0.35s 先结束），与 shell css 过渡对齐。
     navPanelClosing / accountPanelClosing 是面板各自的退出窗口：抽屉关闭时
     nav.open / account.open 在渲染第一拍就变 false，若面板内容同拍卸载，
     .is-closing 下的 cx-mask-down / cx-line-out / cx-nav-fade-out
     （chenxing-design-shell.css 537-549）匹配不到任何元素，逐项退出动画
     永远不会执行；两个退出窗口让最后打开的面板在收拢期间保持渲染（#379）。 */
  const navClosing = useExitDelay(anyOpen, 450)
  const navPanelClosing = useExitDelay(nav.open, 450)
  const accountPanelClosing = useExitDelay(account.open, 450)
  const drawer = useAccordionHeight(anyOpen)
  const name = user?.display_name || user?.username || '辰'
  const avatar = avatarUrl(user)
  const memberId = user?.id != null ? `NO.${String(user.id).padStart(6, '0')}` : 'NO.000000'
  const handle = user?.username ? `@${user.username}` : '@user'

  /* 抽屉内容在退出窗口内的面板选择：open 分支优先——「关汉堡同时开账户」这类
     互斥切换必须立即换面板，不能等旧面板的退出窗口结束；两者都关闭时，各自的
     退出窗口选中最后打开的面板，供 .is-closing 逐项退出动画使用（#379）。 */
  const showNavMenu = nav.open || (!account.open && navPanelClosing)
  const showAccountPanel = account.open || (!nav.open && accountPanelClosing)

  return (
    <>
      <div ref={sentinelRef} aria-hidden="true" className="chenxing-topbar-sentinel" />
      <header
        className="chenxing-topbar"
        data-expanded={expanded || undefined}
        data-open={anyOpen || undefined}
        data-hide-brand-when-expanded={hideBrandWhenExpanded || undefined}
      >
        {/* 胶囊视觉在内层：外层 header 流内高度固定一行（见 shell css），
            抽屉展开只向下溢出覆盖内容，不改变文档高度与滚动条长度。 */}
        <div className="chenxing-topbar-capsule">
          <div className="chenxing-topbar-row">
            {/* 只留字形：50px 行高里放不下两行中文，且首页 hero、控制台侧栏、
                登录面板都已各自承载完整品牌名，顶栏重复一遍只是挤占密度。 */}
            <Link to="/" className="chenxing-topbar-brand" aria-label="返回首页">
              <BrandMark className="chenxing-topbar-mark" />
            </Link>
            {links?.length ? (
              <nav className="chenxing-topbar-links" aria-label="页面导航">
                {links.map((item) => (
                  <a key={item.href} href={item.href}>{item.label}</a>
                ))}
              </nav>
            ) : null}
            {/* 微标签绝对居中且不吃指针：居中与两侧元素宽度解耦，也永不挡住按钮命中区。
                lamalama 行为：页面最顶部（expanded）时中央不显示任何文字，向下滚动
                顶栏收拢成胶囊的同时，文字以乱码逐位解码的方式出现；滚回顶部随
                容器淡出。字符串状态走 ScrambleText，ReactNode 状态保持原样常驻。 */}
            <div className="chenxing-topbar-status" data-topbar-status data-hidden={expanded || undefined}>
              {typeof status === 'string' ? <ScrambleText text={status} active={!expanded} /> : <span>{status}</span>}
              </div>
            <div className="chenxing-topbar-actions">
              {/* 汉堡按钮：点击时打开导航菜单 */}
              <div className="inline-flex" ref={nav.containerRef}>
                <button
                  ref={nav.buttonRef}
                  type="button"
                  className={`chenxing-hamburger${nav.open ? ' is-open' : ''}`}
                  aria-label="打开导航菜单"
                  aria-expanded={nav.open}
                  aria-controls={nav.panelId}
                  aria-haspopup="true"
                  onClick={toggleNav}
                  onKeyDown={nav.onButtonKeyDown}
                >
                  <span /><span /><span />
                </button>
              </div>
              {/* 头像按钮：点击时收缩并打开账户菜单（在抽屉里显示） */}
              {loggedIn ? (
                <div className="inline-flex" ref={account.containerRef}>
                  <button
                    ref={account.buttonRef}
                    type="button"
                    className={`chenxing-avatar chenxing-avatar-trigger h-11 w-11 text-sm${account.open ? ' is-open' : ''}`}
                    aria-label="账户菜单"
                    aria-expanded={account.open}
                    aria-controls={account.panelId}
                    aria-haspopup="true"
                    onClick={toggleAccount}
                    onKeyDown={account.onButtonKeyDown}
                  >
                    <AvatarContent src={avatar} name={name} />
                  </button>
                </div>
              ) : action && actionTo ? (
                <Link to={actionTo} className="chenxing-topbar-cta">{action}</Link>
              ) : null}
            </div>
          </div>
          {/* 抽屉：显示导航菜单或账户信息 */}
          {(anyOpen || navClosing) ? (
            <div className={`chenxing-topbar-drawer${!anyOpen && navClosing ? ' is-closing' : ''}`} style={{ height: `${drawer.height}px` }}>
              <div ref={drawer.innerRef} className="chenxing-topbar-drawer-inner">
                {showNavMenu ? (
                  <NavMenu
                    id={nav.panelId}
                    panelRef={nav.panelRef}
                    onKeyDown={nav.onPanelKeyDown}
                    extra={menuExtra}
                    onNavigate={nav.close}
                  />
                ) : showAccountPanel ? (
                  <div id={account.panelId} data-menu ref={account.panelRef} onKeyDown={account.onPanelKeyDown} className="chenxing-menu cx-nav-panel cx-account-panel">
                    {/* 用户信息头 */}
                    <div className="cx-account-header">
                      <div className="chenxing-avatar h-20 w-20 text-2xl pointer-events-none">
                        <AvatarContent src={avatar} name={name} />
                      </div>
                      <p className="mt-3 text-base font-semibold text-[var(--chenxing-foreground)]">{name}</p>
                      <div className="mt-2.5 grid grid-cols-2 gap-x-8 text-center text-[11px]">
                        <div>
                          <p className="chenxing-caption uppercase tracking-[0.1em]">会员序列</p>
                          <p className="chenxing-mono mt-0.5 text-[var(--chenxing-foreground)]">{memberId}</p>
                        </div>
                        <div>
                          <p className="chenxing-caption uppercase tracking-[0.1em]">@ Handle</p>
                          <p className="chenxing-mono mt-0.5 text-[var(--chenxing-cyan)]">{handle}</p>
                        </div>
                      </div>

                      {/* 配额卡片 */}
                      {entitlements && (entitlements.daily || entitlements.monthly) ? (
                        <div className="mt-4 w-full space-y-2.5 px-2">
                          {entitlements.daily ? (
                            <div className="cx-quota-card">
                              <div className="flex items-center justify-between">
                                <span className="text-xs text-[var(--chenxing-muted-foreground)]">每日授权调用</span>
                                <span className="chenxing-mono text-xs font-semibold">
                                  {entitlements.daily.used} / {typeof entitlements.daily.limit === 'number' ? entitlements.daily.limit : '∞'}
                                </span>
                              </div>
                            </div>
                          ) : null}
                          {entitlements.monthly ? (
                            <div className="cx-quota-card">
                              <div className="flex items-center justify-between">
                                <span className="text-xs text-[var(--chenxing-muted-foreground)]">每月授权调用</span>
                                <span className="chenxing-mono text-xs font-semibold">
                                  {entitlements.monthly.used} / {typeof entitlements.monthly.limit === 'number' ? entitlements.monthly.limit : '∞'}
                                </span>
                              </div>
                            </div>
                          ) : null}
                        </div>
                      ) : null}
                    </div>

                    {/* 菜单项 */}
                    <div className="p-2">
                      <Link to="/console/profile" className="chenxing-menu-item" onClick={account.close}>
                         <Icon name="user" className="text-[var(--chenxing-cyan)]" size={16} />账户设置
                       </Link>
                      <Link to="/console/plans" className="chenxing-menu-item" onClick={account.close}>
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
                        onClick={() => {
                          // 先取得一次性导航意图。草稿守卫拒绝时，既不撤销会话，
                          // 也不关闭菜单；登出完成后提交该意图不会再次询问守卫（#530）。
                          const intent = prepareNavigation('/login')
                          if (!intent) return
                          account.close()
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
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          ) : null}
        </div>
      </header>
      {/* 遮罩只剩压暗+模糊背景这一职责（面板已移进胶囊）。它必须是顶栏的兄弟节点：
          backdrop-filter 的模糊会作用于其下绘制的一切，而 DOM 祖先永远先于后代
          绘制，遮罩若嵌在顶栏内部，顶栏就无法靠 z-index 逃出模糊。做兄弟节点后
          两者同处一个层叠上下文，--chenxing-z-topbar(55) > --chenxing-z-menu(50)
          生效，胶囊连同展开的抽屉一起保持清晰。 */}
      {(anyOpen || navClosing) ? (
        <div
          className={`cx-menu-overlay${anyOpen ? ' is-open' : ''}`}
          onClick={() => {
            nav.close()
            account.close()
          }}
          aria-hidden="true"
        />
      ) : null}
    </>
  )
}
