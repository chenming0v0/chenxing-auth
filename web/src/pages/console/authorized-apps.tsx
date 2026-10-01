import { useCallback, useEffect, useRef, useState } from 'react'
import { apiFetch, type AuthorizedOAuthApp } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Badge, Button, Chip, EmptyState, HudPanel, Icon, Notice, PageIntro } from '@chenxing/ui'
import { formatDate } from '../../data'
import { Link } from '../../router'
import type { MessageTone } from './profile-avatar'
import { RevokeAppDialog } from './revoke-app-dialog'

export function AuthorizedApps() {
  const [apps, setApps] = useState<AuthorizedOAuthApp[]>([])
  const [notice, setNotice] = useState<{ text: string; tone: MessageTone } | null>(null)
  const [busyClientId, setBusyClientId] = useState<string | null>(null)
  const [pendingApp, setPendingApp] = useState<AuthorizedOAuthApp | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [hasData, setHasData] = useState(false)
  /*
   * 单调 request id（#688）：StrictMode 会重放初始 effect，撤销后的静默刷新也可能与
   * 在途请求重叠。普通加载与静默刷新必须共享同一条序列，否则两套函数会互相覆盖，
   * 先发后到的旧快照能让已撤销的授权重新显示为「已连接」。
   */
  const listRequestIdRef = useRef(0)
  const revokingRef = useRef(false)
  const notify = (text: string, tone: MessageTone) => setNotice({ text, tone })
  const warn = (text: string) => notify(text, 'warning')

  const loadApps = useCallback(async (): Promise<void> => {
    const requestId = ++listRequestIdRef.current
    setLoading(true)
    setLoadError(null)
    setNotice(null)
    try {
      const response = await apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps')
      if (requestId !== listRequestIdRef.current) return
      setApps(response.items)
      setHasData(true)
    } catch (reason) {
      if (requestId !== listRequestIdRef.current) return
      const message = reason instanceof Error ? reason.message : '应用列表加载失败。'
      setLoadError(message)
      warn(message)
    } finally {
      // 过期请求不得提前结束更新请求的 loading，否则用户会在数据收敛前继续操作。
      if (requestId === listRequestIdRef.current) setLoading(false)
    }
  }, [])

  async function refreshAppsSilently(): Promise<void> {
    const requestId = ++listRequestIdRef.current
    try {
      const response = await apiFetch<{ items: AuthorizedOAuthApp[] }>('/api/v1/auth/authorized-apps')
      if (requestId !== listRequestIdRef.current) return
      setApps(response.items)
      setHasData(true)
    } catch {
      // 撤销已经生效时保留旧列表与成功提示，不用刷新错误覆盖成功事实。
    }
  }

  useEffect(() => {
    void loadApps()
    // 卸载后让在途响应失效，避免对已卸载组件 setState
    return () => { listRequestIdRef.current += 1 }
  }, [loadApps])

  async function revokeApp(app: AuthorizedOAuthApp) {
    // ref 挡住「busy 还没重渲染」时的第二次确认，避免同一条授权被删两次。
    if (revokingRef.current) return
    revokingRef.current = true
    setBusyClientId(app.client_id)
    setNotice(null)
    try {
      await apiFetch<void>(`/api/v1/auth/authorized-apps/${encodeURIComponent(app.client_id)}`, { method: 'DELETE' })
      setApps((current) => current.filter((item) => item.client_id !== app.client_id))
      notify('应用授权已撤销。', 'success')
      setPendingApp(null)
      await refreshAppsSilently()
    } catch (reason) {
      warn(reason instanceof Error ? reason.message : '应用授权撤销失败。')
      // 失败提示画在页面上；对话框不关的话遮罩会把它挡住。
      setPendingApp(null)
    } finally {
      revokingRef.current = false
      setBusyClientId(null)
    }
  }

  const openScopes = apps.reduce((sum, app) => sum + app.scopes.length, 0)

  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Connections"
        title="已授权应用"
        description="管理已通过辰星通行证登录的第三方应用与其权限范围。"
        action={<Link className="chenxing-btn-ghost" to="/console/integrate">接入应用</Link>}
      />
      {notice ? <div className="mb-4"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}
      {loadError ? <div className="mb-4"><Notice tone="warning">应用列表不可用。{loadError} <button type="button" className="chenxing-link ml-2" onClick={() => void loadApps()}>重试</button></Notice></div> : null}
      <div className="mb-6 grid grid-cols-3 gap-3 sm:gap-4">
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">已授权应用</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">{loading || loadError ? '—' : apps.length}</p></HudPanel>
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">开放权限域</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">{loading || loadError ? '—' : openScopes}</p></HudPanel>
        <HudPanel className="!p-4 sm:!p-5"><p className="chenxing-mono text-[10px] uppercase tracking-[0.2em] text-[var(--chenxing-muted-foreground)]">服务端记录</p><p className="chenxing-display mt-2 text-3xl font-bold text-aurora">LIVE</p></HudPanel>
      </div>
      <div className="space-y-4">
        {apps.map((app) => (
          <HudPanel as="article" key={app.client_id} className="!p-5 sm:!p-6">
            <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0 flex-1">
                <div className="flex items-start gap-4">
                  <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl border border-[rgba(125,211,252,0.4)] bg-[rgba(56,189,248,0.12)] text-[var(--chenxing-cyan)] shadow-[var(--chenxing-shadow-cyan-float)]">
                    <Icon name="box" size={22} />
                  </span>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="chenxing-h3">{app.client_name}</h3>
                      <Badge tone="success"><Icon name="check" size={12} />已连接</Badge>
                    </div>
                    <p className="chenxing-caption mt-1 chenxing-mono">{app.client_id}</p>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {app.scopes.map((scope) => <Chip key={scope}><Icon name="fingerprint" size={14} />{scope}</Chip>)}
                </div>
                <p className="chenxing-caption mt-3">最近授权 {formatDate(app.updated_at)}</p>
              </div>
              <div className="flex shrink-0 items-center gap-4 lg:flex-col lg:items-end lg:gap-3">
                <Button variant="ghost" icon="eye" disabled title="详情接口尚未提供">查看详情</Button>
                <Button variant="danger" icon="unlink" disabled={busyClientId !== null} onClick={() => { setNotice(null); setPendingApp(app) }}>撤销授权</Button>
              </div>
            </div>
          </HudPanel>
        ))}
        {!loading && !loadError && !apps.length ? (
          <HudPanel>
            <EmptyState icon="shield-check" title="暂无已授权应用" description="完成 OAuth 授权后，应用会显示在这里。" action={<Link className="chenxing-btn-primary mt-2" to="/console/playground">去授权测试</Link>} />
          </HudPanel>
        ) : null}
      </div>
      {pendingApp ? (
        <RevokeAppDialog
          name={pendingApp.client_name}
          busy={busyClientId !== null}
          onCancel={() => setPendingApp(null)}
          onConfirm={() => { void revokeApp(pendingApp) }}
        />
      ) : null}
    </ConsoleLayout>
  )
}
