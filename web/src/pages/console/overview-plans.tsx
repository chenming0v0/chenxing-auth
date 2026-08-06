import { useEffect, useState } from 'react'
import { Link } from '../../router'
import { useAuth } from '../../auth-state'
import { apiFetch, type AuthorizedOAuthApp, type OwnedOAuthClient, type SessionItem } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Chip, HudPanel, Icon, Notice, PageIntro } from '../../components/ui'
import { formatDate, greeting } from '../../data'
import {
  entitlementState, entitlementView, Meter, SelfServiceClosedBlock,
  SELF_SERVICE_CLOSED_BODY, SELF_SERVICE_CLOSED_KEPT, SELF_SERVICE_CLOSED_TITLE, useEntitlements,
} from './shared'

export function ConsoleOverview() {
  const { user } = useAuth()
  const entitlementQuery = useEntitlements()
  const { error: entitlementError, retry } = entitlementQuery
  const plans = entitlementState(entitlementQuery)
  const [clients, setClients] = useState<OwnedOAuthClient[]>([])
  const [sessions, setSessions] = useState<SessionItem[]>([])
  const [apps, setApps] = useState<AuthorizedOAuthApp[]>([])
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let active = true
    void Promise.all([
      apiFetch<{ items: OwnedOAuthClient[] }>('/api/v1/auth/oauth-clients'),
      apiFetch<{ items: SessionItem[] }>('/api/v1/auth/sessions'),
      apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps'),
    ]).then(([clientResponse, sessionResponse, appResponse]) => {
      if (!active) return
      setClients(clientResponse.items)
      setSessions(sessionResponse.items)
      setApps(appResponse.items)
    }).catch((reason: unknown) => {
      if (active) setError(reason instanceof Error ? reason.message : '账户摘要加载失败。')
    }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])

  const name = user?.display_name || user?.username || '用户'
  const openScopes = apps.reduce((sum, app) => sum + app.scopes.length, 0)

  return (
    <ConsoleLayout>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">// Passport Console</p>
          <h1 className="chenxing-h1 mt-2">{greeting()}，{name}</h1>
          <p className="chenxing-caption mt-1">天穹辰星 · 辰星通行证 · {new Date().toLocaleDateString('zh-CN')} · 你的星际身份状态一切正常</p>
        </div>
        {/* 未开放自助接入时不把用户推向一个不能提交的创建入口，只保留查看已接入应用 */}
        <Link to="/console/integrate" className="chenxing-btn-primary px-5 py-2.5 text-sm">
          <Icon name={plans.kind === 'closed' ? 'code-2' : 'plus'} size={16} />
          {plans.kind === 'closed' ? '查看接入应用' : '接入新应用'}
        </Link>
      </div>

      {/* 只在真实加载失败时报警；plan 为 null 属于正常状态，不走这里 */}
      {(error || entitlementError) ? (
        <div className="mt-5"><Notice tone="warning">{error || entitlementError}<button className="chenxing-link ml-2" type="button" onClick={retry}>重试</button></Notice></div>
      ) : null}

      <div className="mt-7 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <HudPanel>
          <div className="flex items-center justify-between"><span className="chenxing-caption">已授权应用</span><Icon name="shield-check" className="text-[var(--chenxing-cyan)]" size={16} /></div>
          <p className="chenxing-display mt-3 text-3xl font-bold">{loading ? '—' : apps.length}</p>
          <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">开放权限域 · {loading ? '—' : openScopes}</p>
        </HudPanel>
        <HudPanel>
          <div className="flex items-center justify-between"><span className="chenxing-caption">接入应用</span><Icon name="code-2" className="text-[var(--chenxing-cyan)]" size={16} /></div>
          <p className="chenxing-display mt-3 text-3xl font-bold">{loading ? '—' : clients.length}</p>
          <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">当前账号拥有</p>
        </HudPanel>
        <HudPanel>
          <div className="flex items-center justify-between"><span className="chenxing-caption">活跃会话</span><Icon name="activity" className="text-[var(--chenxing-cyan)]" size={16} /></div>
          <p className="chenxing-display mt-3 text-3xl font-bold">{loading ? '—' : sessions.length}</p>
          <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">服务端当前列表</p>
        </HudPanel>
        <HudPanel>
          <div className="flex items-center justify-between">
            <span className="chenxing-caption">当前套餐</span>
            <Icon name={plans.kind === 'closed' ? 'lock-keyhole' : 'crown'} className={plans.kind === 'closed' ? 'text-[var(--chenxing-muted-foreground)]' : 'text-[var(--chenxing-cyan)]'} size={16} />
          </div>
          <p className={`mt-3 font-bold ${plans.kind === 'closed' ? 'chenxing-body text-2xl' : 'chenxing-display text-3xl'}`}>
            {plans.kind === 'ready' ? plans.plan.code : plans.kind === 'closed' ? '未开放' : '—'}
          </p>
          <p className="chenxing-mono mt-2 text-xs text-[var(--chenxing-muted-foreground)]">
            {plans.kind === 'ready' ? plans.plan.name
              : plans.kind === 'closed' ? '平台未开放自助接入'
              : plans.kind === 'loading' ? '正在读取套餐数据' : '套餐数据暂不可用'}
          </p>
        </HudPanel>
      </div>

      <div className="mt-6 grid gap-4 xl:grid-cols-2">
        <HudPanel>
          <div className="mb-4 flex items-center justify-between">
            <div><h2 className="chenxing-h2">账户状态</h2><p className="chenxing-caption mt-1">公开资料和当前会话有效期</p></div>
            <Icon name="user" className="text-[var(--chenxing-cyan)]" size={18} />
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] p-4">
              <div>
                <p className="chenxing-body text-sm font-semibold">{name}</p>
                <p className="chenxing-caption chenxing-mono">{user?.email}</p>
              </div>
              <Badge tone="success">{user?.status || 'active'}</Badge>
            </div>
            <div className="flex items-center justify-between rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(255,255,255,0.02)] p-4">
              <div>
                <p className="chenxing-body text-sm font-semibold">当前会话</p>
                <p className="chenxing-caption">到期时间由服务端返回</p>
              </div>
              <span className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{user ? formatDate(user.current_session_expires_at) : '—'}</span>
            </div>
          </div>
        </HudPanel>
        <HudPanel>
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="chenxing-h2">当前权益</h2>
              <p className="chenxing-caption mt-1">
                {plans.kind === 'ready' ? `${plans.plan.name} · ${plans.plan.validity === 'permanent' ? '永久有效' : formatDate(plans.plan.validity)}`
                  : plans.kind === 'closed' ? '当前没有可用额度'
                  : '服务端权益数据'}
              </p>
            </div>
            <Icon name={plans.kind === 'closed' ? 'lock-keyhole' : 'crown'} className={plans.kind === 'closed' ? 'text-[var(--chenxing-muted-foreground)]' : 'text-[var(--chenxing-cyan)]'} size={18} />
          </div>
          {plans.kind === 'ready' ? (
            <div className="space-y-4">
              {plans.data.entitlements.slice(0, 4).map((item) => {
                const view = entitlementView(item)
                return (
                  <div key={item.key}>
                    <div className="flex items-center justify-between gap-3">
                      <span className="chenxing-body text-sm">{item.label}</span>
                      <strong className="chenxing-mono text-sm">{item.used}{view.hasLimit ? ` / ${item.limit}` : view.unlimited ? ' / ∞' : ''}</strong>
                    </div>
                    {view.hasLimit ? <Meter value={view.progress} /> : null}
                  </div>
                )
              })}
              <Link className="chenxing-link inline-flex items-center gap-1.5" to="/console/plans">查看套餐权益 <Icon name="arrow-up-right" size={14} /></Link>
            </div>
          ) : plans.kind === 'closed' ? (
            <SelfServiceClosedBlock>
              <Link className="chenxing-link inline-flex items-center gap-1.5" to="/console/plans">查看套餐与权益 <Icon name="arrow-up-right" size={14} /></Link>
            </SelfServiceClosedBlock>
          ) : <Notice>{plans.kind === 'loading' ? '正在加载权益数据。' : '权益数据暂不可用，可稍后重试。'}</Notice>}
        </HudPanel>
      </div>

      <HudPanel className="mt-6 !p-0 overflow-hidden">
        <div className="flex items-center justify-between px-6 py-5">
          <div><h2 className="chenxing-h2">最近活动</h2><p className="chenxing-caption mt-1">来自当前会话与授权记录的摘要</p></div>
        </div>
        <div className="cx-table-wrap border-0 rounded-none">
          <table className="cx-table min-w-[720px]">
            <thead>
              <tr>
                <th className="chenxing-body px-6 py-3 text-[0.9375rem] font-medium text-[var(--chenxing-muted-foreground)]">时间</th>
                <th className="chenxing-body px-6 py-3 text-[0.9375rem] font-medium text-[var(--chenxing-muted-foreground)]">应用</th>
                <th className="chenxing-body px-6 py-3 text-[0.9375rem] font-medium text-[var(--chenxing-muted-foreground)]">事件</th>
                <th className="chenxing-body px-6 py-3 text-[0.9375rem] font-medium text-[var(--chenxing-muted-foreground)]">状态</th>
              </tr>
            </thead>
            <tbody>
              {apps.slice(0, 4).map((app) => (
                <tr key={app.client_id}>
                  <td className="chenxing-mono px-6 py-4 text-xs text-[var(--chenxing-muted-foreground)]">{formatDate(app.updated_at)}</td>
                  <td className="chenxing-body px-6 py-4 text-sm">{app.client_name}</td>
                  <td className="chenxing-body px-6 py-4 text-sm">授权范围 · {app.scopes.join(' ')}</td>
                  <td className="px-6 py-4"><span className="chenxing-body text-sm font-bold text-[var(--chenxing-success)]">成功</span></td>
                </tr>
              ))}
              {!loading && !apps.length ? (
                <tr><td colSpan={4} className="px-6 py-10 text-center"><span className="chenxing-caption">暂无最近授权活动</span></td></tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </HudPanel>
    </ConsoleLayout>
  )
}

export function ConsolePlans() {
  const query = useEntitlements()
  const { error, retry } = query
  const plans = entitlementState(query)
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Subscription"
        title="套餐与权益"
        description={plans.kind === 'closed' ? '平台尚未开放自助接入，当前没有可用的套餐额度' : '管理你的辰星通行证订阅与资源额度'}
      />
      {error ? <div className="mb-4"><Notice tone="warning">{error}<button className="chenxing-link ml-2" type="button" onClick={retry}>重试</button></Notice></div> : null}
      {plans.kind === 'loading' ? <HudPanel><Notice>正在加载服务端权益数据。</Notice></HudPanel> : null}
      {plans.kind === 'closed' ? (
        <HudPanel className="p-6">
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div className="min-w-0">
              <div className="flex items-center gap-3">
                <span className="inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border-strong)] bg-[var(--chenxing-muted)] text-[var(--chenxing-muted-foreground)]">
                  <Icon name="lock-keyhole" size={20} />
                </span>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="chenxing-h2">{SELF_SERVICE_CLOSED_TITLE}</span>
                    <Chip>无可用套餐</Chip>
                  </div>
                  <p className="chenxing-caption mt-1">{SELF_SERVICE_CLOSED_BODY}</p>
                </div>
              </div>
              <ul className="mt-5 space-y-2">
                {[
                  '当前账号没有套餐额度，页面不展示配额数字。',
                  SELF_SERVICE_CLOSED_KEPT,
                  '管理员为你分配套餐后，这里会显示对应的额度明细。',
                ].map((line) => (
                  <li key={line} className="chenxing-caption flex items-start gap-2">
                    <Icon name="circle" className="mt-1 shrink-0 text-[var(--chenxing-muted-foreground)]" size={9} />
                    <span>{line}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <Button variant="ghost" icon="refresh-cw" onClick={retry}>重新检查</Button>
            </div>
          </div>
        </HudPanel>
      ) : null}
      {plans.kind === 'ready' ? (
        <>
          <HudPanel className="p-6">
            <div className="flex flex-wrap items-start justify-between gap-6">
              <div className="min-w-0">
                <div className="flex items-center gap-3">
                  <span className="chenxing-avatar h-11 w-11"><Icon name="crown" size={20} /></span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="chenxing-h2">{plans.plan.name}</span>
                      <Chip>当前套餐</Chip>
                    </div>
                    <p className="chenxing-caption mt-1">{plans.plan.description || '你正在使用服务端返回的当前套餐。'}</p>
                  </div>
                </div>
                <div className="mt-5 flex flex-wrap items-baseline gap-x-6 gap-y-2">
                  <span className="chenxing-display text-aurora text-3xl">{plans.plan.code}</span>
                  <span className="chenxing-caption flex items-center gap-1.5">
                    <Icon name="calendar-clock" className="text-[var(--chenxing-cyan)]" size={16} />
                    {plans.plan.validity === 'permanent' ? '永久有效' : `有效至 ${formatDate(plans.plan.validity)}`}
                  </span>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <Button icon="settings-2" disabled title="订阅管理尚未提供">管理订阅</Button>
                <Button variant="ghost" icon="receipt" disabled title="账单接口尚未提供">查看账单</Button>
              </div>
            </div>
          </HudPanel>

          <div className="mt-4 grid gap-4 sm:grid-cols-3">
            {plans.data.entitlements.map((item) => {
              const view = entitlementView(item)
              return (
                <HudPanel key={item.key} className="p-5">
                  <div className="flex items-center justify-between">
                    <span className="chenxing-avatar h-9 w-9"><Icon name="activity" size={16} /></span>
                    <span className="chenxing-mono text-sm text-[var(--chenxing-cyan)]">{view.hasLimit ? `${Math.round(view.progress)}%` : '∞'}</span>
                  </div>
                  <p className="chenxing-body mt-4 text-sm font-semibold">{item.label}</p>
                  {view.hasLimit ? <Meter value={view.progress} /> : <div className="mt-3 h-2" />}
                  <p className="chenxing-caption mt-2">
                    {view.hasLimit ? `${item.used} / ${item.limit}` : view.unlimited ? `${item.used} / ∞` : `${item.used}`}
                  </p>
                </HudPanel>
              )
            })}
          </div>

          <HudPanel className="mt-4 p-6">
            <div className="mb-5">
              <h2 className="chenxing-h2">权益明细</h2>
              <p className="chenxing-caption mt-1">额度与限制均来自服务端。升级动作需要产品侧提供对应流程。</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
              {plans.data.entitlements.map((item) => {
                const view = entitlementView(item)
                return (
                  <HudPanel key={`detail-${item.key}`} className="p-5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="chenxing-h3">{item.label}</span>
                      <Badge tone="success">实时</Badge>
                    </div>
                    <p className="chenxing-mono mt-3 text-sm text-[var(--chenxing-ice)]">{item.key}</p>
                    <p className="chenxing-caption mt-3">
                      {view.hasLimit ? `已用 ${item.used}，剩余 ${view.remaining}` : view.unlimited ? '该权益由服务端标记为无限额度。' : '该权益没有数值上限概念。'}
                    </p>
                    <Button variant="ghost" className="mt-5 w-full justify-center" disabled title="升级流程尚未提供">联系支持处理升级</Button>
                  </HudPanel>
                )
              })}
            </div>
            <div className="mt-5"><Notice tone="info">当前 API 只提供权益查询，页面不会将选择操作伪装成已扣款或已升级。</Notice></div>
          </HudPanel>
        </>
      ) : null}
    </ConsoleLayout>
  )
}


