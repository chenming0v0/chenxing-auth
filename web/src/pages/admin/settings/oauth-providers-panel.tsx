import { useRef, useState } from 'react'
import { apiFetch, type OAuthProviderSummary } from '../../../api'
import { Badge, Button, EmptyState, Icon, Notice } from '../../../components/ui'
import { DataTable, TablePanel } from '../../../components/data-table'
import { OAuthProviderFormDialog, toInput, type ProviderForm } from './oauth-provider-form-dialog'
import { useSettingsResource, type SettingsPanelProps } from './panel'

type StatusAction = 'enable' | 'disable'

/**
 * 「配置已经写进库、但状态切换没成功」的部分成功状态（Issue #277）。
 *
 * 创建 provider 是两次独立请求：POST 落库（后端默认停用），再 POST /enable 切状态。
 * 第二步失败时 provider 已经存在，重试必须只重放状态切换；再走一次创建只会撞 slug 冲突，
 * 把一个可修复的问题变成看起来无解的报错。
 */
type PendingStatusChange = {
  slug: string
  name: string
  action: StatusAction
  /** true 表示 provider 是本次刚创建出来的，文案要说清「已创建但未启用」 */
  created: boolean
  reason: string
}

type StatusResult = { ok: true; stateVersion: number } | { ok: false; reason: string }

function errorText(reason: unknown, fallback: string): string {
  return reason instanceof Error ? reason.message : fallback
}

function actionLabel(action: StatusAction): string {
  return action === 'enable' ? '启用' : '禁用'
}

/* 列表是状态切换是否成功的唯一权威来源：provider 已经到达目标状态（或者干脆不存在了）时，
   重试提示必须自己消失，不能靠用户手动清理。 */
function reconcile(current: PendingStatusChange | null, list: OAuthProviderSummary[]): PendingStatusChange | null {
  if (!current) return null
  const provider = list.find((item) => item.slug === current.slug)
  /* A refresh started immediately after creation can still return the old
     list. Missing data is inconclusive; only an observed target state may
     consume the retry notice. */
  if (!provider) return current
  const active = provider.status === 'active'
  return active === (current.action === 'enable') ? null : current
}

function pendingMessage(pending: PendingStatusChange): string {
  const label = actionLabel(pending.action)
  const head = pending.created
    ? `${pending.name} 已创建成功，但${label}失败，当前处于已禁用状态。`
    : `${pending.name} 的配置已保存成功，但${label}失败，状态未变更。`
  return `${head}原因：${pending.reason}配置无需重新填写，可直接重试${label}。`
}

export function OAuthProvidersPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [providers, setProviders] = useState<OAuthProviderSummary[] | null>(null)
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState<OAuthProviderSummary | null>(null)
  const [busy, setBusy] = useState(false)
  // setBusy 要等下一帧才进 render；同一事件循环里的二次 submit / Enter 必须靠 ref 拦住。
  const busyRef = useRef(false)
  const [pending, setPending] = useState<PendingStatusChange | null>(null)

  /* reload 引用稳定，因此保存与启停后的刷新只重取本面板列表，
     不会因为消息状态变化把其它面板的草稿一起冲掉（#268）。 */
  const { loading, reload } = useSettingsResource<OAuthProviderSummary[]>({
    path: '/api/v1/admin/oauth/providers',
    onMessage,
    failureMessage: 'OAuth 提供商加载失败。',
    apply: (list) => {
      setProviders(list)
      setPending((current) => reconcile(current, list))
    },
    onFailure: () => setProviders([]),
  })

  function openCreate() {
    setEditing(null)
    setOpen(true)
  }

  function openEdit(provider: OAuthProviderSummary) {
    setEditing(provider)
    setOpen(true)
  }

  async function applyStatus(slug: string, action: StatusAction, expectedVersion: number): Promise<StatusResult> {
    try {
      const result = await apiFetch<{ state_version: number }>(`/api/v1/admin/oauth/providers/${encodeURIComponent(slug)}/${action}`, {
        method: 'POST',
        body: JSON.stringify({ expected_version: expectedVersion }),
      })
      return { ok: true, stateVersion: result.state_version }
    } catch (reason) {
      return { ok: false, reason: errorText(reason, 'OAuth 提供商状态更新失败。') }
    }
  }

  /** 写入配置本身（创建或更新），返回后续状态切换要用的 slug。失败时抛错，弹层保持打开让用户改。 */
  async function persist(form: ProviderForm, target: OAuthProviderSummary | null): Promise<OAuthProviderSummary> {
    if (target) {
      const response = await apiFetch<OAuthProviderSummary>(`/api/v1/admin/oauth/providers/${encodeURIComponent(target.slug)}`, {
        method: 'PUT',
        body: JSON.stringify({ ...toInput(form), expected_version: target.state_version ?? 1 }),
      })
      return { ...target, ...response }
    }
    return apiFetch<OAuthProviderSummary>('/api/v1/admin/oauth/providers', {
      method: 'POST',
      body: JSON.stringify(toInput(form)),
    })
  }

  async function save(form: ProviderForm) {
    /* 防重入：保存请求在途时忽略重复提交（Issue #369）。弹层内 Enter 隐式提交会绕过
       已禁用的保存按钮直达 onSubmit，只有这里的入口守卫能拦下第二条在途请求
       （创建场景会撞出第二次 POST）。与其它设置面板的 save() 守卫保持一致。 */
    if (busyRef.current) return
    const target = editing
    busyRef.current = true
    setBusy(true)
    try {
      const saved = await persist(form, target)
      const slug = saved.slug
      const currentActive = saved.status === 'active'
      const action: StatusAction | null = form.enabled === currentActive ? null : form.enabled ? 'enable' : 'disable'
      const status = action ? await applyStatus(slug, action, saved.state_version ?? 1) : { ok: true as const, stateVersion: saved.state_version ?? 1 }
      setOpen(false)
      if (action && !status.ok) {
        const failure: PendingStatusChange = {
          slug,
          name: form.name.trim() || slug,
          action,
          created: !target,
          reason: status.reason,
        }
        setPending(failure)
        onMessage(pendingMessage(failure), 'warning')
      } else {
        /* 成功路径不能盲清 pending（#367）：pending 可能属于另一个 provider，
           一次无关的保存不该拿走它的重试入口。同一 provider 的旧提示由本次保存取代
           （用户已重新表达意图）；其它 provider 的提示留给紧随其后的 reload，
           由 reconcile 用最新列表裁决。 */
        setPending((current) => (current && current.slug === slug ? null : current))
        onMessage(target ? 'OAuth 提供商已更新。' : 'OAuth 提供商已创建。')
      }
      await reload()
    } catch (reason) {
      onMessage(errorText(reason, 'OAuth 提供商保存失败。'), 'warning')
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }

  /** 只重放状态切换，不再触碰创建与更新接口。 */
  async function retryPending() {
    if (!pending || busyRef.current) return
    busyRef.current = true
    setBusy(true)
    try {
      const current = providers?.find((provider) => provider.slug === pending.slug)
      if (!current) return
      const status = await applyStatus(pending.slug, pending.action, current.state_version ?? 1)
      if (status.ok) {
        setPending(null)
        onMessage(`已${actionLabel(pending.action)} ${pending.name}。`)
      } else {
        const failure = { ...pending, reason: status.reason }
        setPending(failure)
        onMessage(pendingMessage(failure), 'warning')
      }
      await reload()
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }

  async function toggleStatus(provider: OAuthProviderSummary) {
    if (busyRef.current) return
    const action: StatusAction = provider.status === 'active' ? 'disable' : 'enable'
    const label = actionLabel(action)
    const consequence = action === 'disable'
      ? '禁用后，用户将无法再通过该提供商登录。'
      : '启用后，用户可以重新通过该提供商登录。'
    if (!window.confirm(`确认${label} ${provider.name} 吗？\n${consequence}`)) return
    busyRef.current = true
    setBusy(true)
    try {
      const status = await applyStatus(provider.slug, action, provider.state_version ?? 1)
      if (status.ok) onMessage(`已${label} ${provider.name}。`)
      else onMessage(status.reason, 'warning')
      await reload()
    } finally {
      busyRef.current = false
      setBusy(false)
    }
  }

  return (
    <>
      <TablePanel
        icon="link"
        title="自定义 OAuth 2.0 提供商"
        description="按 OAuth 2.0 授权码流程 + UserInfo 接入 GitHub Enterprise、GitLab、Gitea、Keycloak 等身份提供商。身份字段只取自 UserInfo 响应，本平台不验证 ID Token。"
        action={<Button icon="plus" onClick={openCreate}>添加 OAuth 提供商</Button>}
        notice={pending ? (
          <Notice tone="warning">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <span>{pendingMessage(pending)}</span>
              <div className="flex shrink-0 items-center gap-3">
                <Button icon="refresh-cw" onClick={() => void retryPending()} disabled={busy}>
                  {`重试${actionLabel(pending.action)}`}
                </Button>
                <Button variant="ghost" onClick={() => setPending(null)}>忽略</Button>
              </div>
            </div>
          </Notice>
        ) : null}
      >
        <DataTable
          minWidth={820}
          columns={['图标', '名称', 'Slug', '状态', 'Client ID', 'Client Secret', { label: '操作', align: 'right' }]}
          /* 加载空行只在「首次加载且尚无数据」时出现；reload 期间 providers 仍持有旧数据，
             此时只渲染数据行，不叠加空行，避免两套内容同时出现（Issue #388）。 */
          empty={loading && !providers ? '正在加载 OAuth 提供商。' : providers?.length ? null : (
            <EmptyState
              icon="link"
              title="尚未配置外部身份提供商"
              description="添加提供 OAuth 2.0 授权码流程和 UserInfo 端点的发行者后，用户可在登录页选择外部身份。"
              action={<Button icon="plus" onClick={openCreate}>添加 OAuth 提供商</Button>}
            />
          )}
        >
          {providers?.map((provider) => (
            <tr key={provider.slug}>
              <td>
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-[var(--chenxing-radius-md)] border border-[var(--chenxing-border)] bg-[rgba(56,189,248,0.1)]">
                  <Icon name="shield" className="text-[var(--chenxing-cyan)]" size={16} />
                </span>
              </td>
              <td className="chenxing-body text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span>{provider.name}</span>
                  {provider.email_verified_claim?.trim() ? null : (
                    <Badge tone="warning">
                      <Icon name="alert-triangle" size={12} />
                      缺少 Email Verified Claim
                    </Badge>
                  )}
                </div>
              </td>
              <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{provider.slug}</td>
              <td>
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={provider.status === 'active' ? 'success' : 'warning'}>
                    {provider.status === 'active' ? '已启用' : '已禁用'}
                  </Badge>
                  {pending?.slug === provider.slug ? (
                    <Badge tone="warning">
                      <Icon name="alert-triangle" size={12} />
                      {`${actionLabel(pending.action)}失败`}
                    </Badge>
                  ) : null}
                </div>
              </td>
              <td className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">
                {provider.client_id.length > 18 ? `${provider.client_id.slice(0, 18)}...` : provider.client_id}
              </td>
              <td>
                {provider.client_secret_configured ? (
                  <Badge tone="success">
                    <Icon name="check" size={12} />
                    已配置
                  </Badge>
                ) : (
                  <Badge tone="warning">
                    <Icon name="alert-triangle" size={12} />
                    未配置
                  </Badge>
                )}
              </td>
              <td>
                <div className="flex items-center justify-end gap-3">
                  <button type="button" className="chenxing-link chenxing-row-action" onClick={() => openEdit(provider)}>编辑</button>
                  <button type="button" className="chenxing-link chenxing-row-action" style={{ color: 'var(--chenxing-error)' }} onClick={() => void toggleStatus(provider)} disabled={busy}>
                    {provider.status === 'active' ? '禁用' : '启用'}
                  </button>
                </div>
              </td>
            </tr>
          ))}
        </DataTable>
      </TablePanel>

      {open ? (
        <OAuthProviderFormDialog
          key={editing?.slug ?? 'create'}
          editing={editing}
          busy={busy}
          onSubmit={(form) => void save(form)}
          onClose={() => setOpen(false)}
          onMessage={onMessage}
          onDirtyChange={onDirtyChange}
        />
      ) : null}
    </>
  )
}
