import { useCallback, useEffect, useRef, useState } from 'react'
import { Badge, Button, EmptyState, HudPanel, Notice, PageIntro } from '@chenxing/ui'
import {
  createAccountPortalBinding,
  listAccountPortalBindings,
  listAccountPortalProviders,
  newPortalIdempotencyKey,
  refreshAccountPortalBinding,
  syncAccountPortalBinding,
  unlinkAccountPortalBinding,
} from '../../account-portal-api'
import type { AccountPortalBinding, AccountPortalPublicProvider } from '../../account-portal-types'
import { ConsoleLayout } from '../../components/shells'
import { formatDate } from '../../data'
import { useMutationLock } from '../../use-mutation-lock'
import { BindPortalDialog, UnlinkPortalDialog } from './account-portal-dialogs'

type LoadState = { kind: 'loading' } | { kind: 'ready' } | { kind: 'error'; message: string }
type DialogState =
  | { kind: 'bind'; provider: AccountPortalPublicProvider }
  | { kind: 'unlink'; binding: AccountPortalBinding }

export function AccountPortalPage() {
  const [providers, setProviders] = useState<AccountPortalPublicProvider[]>([])
  const [bindings, setBindings] = useState<AccountPortalBinding[]>([])
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [notice, setNotice] = useState<{ text: string; tone: 'success' | 'warning' } | null>(null)
  const [dialog, setDialog] = useState<DialogState | null>(null)
  const [dialogError, setDialogError] = useState<string | null>(null)
  const [pendingId, setPendingId] = useState<string | null>(null)
  const requestIdRef = useRef(0)
  const mutationLock = useMutationLock()

  const load = useCallback(async () => {
    const requestId = ++requestIdRef.current
    const [bindingsResult, providersResult] = await Promise.allSettled([
      listAccountPortalBindings(),
      listAccountPortalProviders(),
    ])
    if (requestId !== requestIdRef.current) return
    if (bindingsResult.status === 'fulfilled') {
      setBindings(bindingsResult.value)
      setState({ kind: 'ready' })
    } else {
      const message = bindingsResult.reason instanceof Error ? bindingsResult.reason.message : '账号门户加载失败。'
      setBindings([])
      setState({ kind: 'error', message })
    }
    if (providersResult.status === 'fulfilled') setProviders(providersResult.value)
    else {
      setProviders([])
      setNotice({ text: '绑定入口暂时不可用，已有绑定仍可查看。', tone: 'warning' })
    }
  }, [])

  useEffect(() => {
    void load()
    return () => { requestIdRef.current += 1 }
  }, [load])

  function providerName(providerId: string, issuer: string): string {
    return providers.find((item) => item.id === providerId)?.display_name ?? issuer
  }

  async function bind(provider: AccountPortalPublicProvider, identifier: string, secret: string): Promise<boolean> {
    setDialogError(null)
    return await mutationLock.run(async () => {
      try {
        const bound = await createAccountPortalBinding(
          { provider_id: provider.id, identifier, secret },
          newPortalIdempotencyKey(),
        )
        setBindings((current) => [bound, ...current.filter((item) => item.id !== bound.id)])
        setNotice({ text: `已绑定 ${provider.display_name}。`, tone: 'success' })
        return true
      } catch (error) {
        setDialogError(error instanceof Error ? error.message : '绑定失败。')
        return false
      }
    }) === true
  }

  async function runBindingAction(binding: AccountPortalBinding, action: 'refresh' | 'sync' | 'unlink'): Promise<boolean> {
    setPendingId(binding.id)
    return await mutationLock.run(async () => {
      try {
        if (action === 'unlink') {
          await unlinkAccountPortalBinding(binding.id)
          setBindings((current) => current.filter((item) => item.id !== binding.id))
          setNotice({ text: '绑定已解除。', tone: 'success' })
        } else {
          const next = action === 'refresh'
            ? await refreshAccountPortalBinding(binding.id, newPortalIdempotencyKey())
            : await syncAccountPortalBinding(binding.id)
          setBindings((current) => current.map((item) => item.id === next.id ? next : item))
          setNotice({ text: action === 'refresh' ? '令牌已刷新。' : '快照已同步。', tone: 'success' })
        }
        return true
      } catch (error) {
        const text = error instanceof Error ? error.message : '操作失败。'
        if (dialog?.kind === 'unlink') setDialogError(text)
        else setNotice({ text, tone: 'warning' })
        return false
      } finally {
        setPendingId(null)
      }
    }) === true
  }

  const boundIds = new Set(bindings.map((item) => item.provider_id))
  const available = providers.filter((item) => !boundIds.has(item.id))

  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Account · 账号门户"
        title="账号门户"
        description="连接通用账号提供方。平台只做只读授权，不会保存你输入的账号密码。"
        action={<Button variant="ghost" icon="refresh-cw" disabled={state.kind === 'loading' || mutationLock.busy} onClick={() => void load()}>刷新</Button>}
      />
      {notice ? <div className="mb-4"><Notice tone={notice.tone}>{notice.text}</Notice></div> : null}
      {state.kind === 'loading' ? <HudPanel aria-busy="true"><div className="h-24 animate-pulse rounded bg-[var(--chenxing-muted)]" /></HudPanel> : null}
      {state.kind === 'error' ? (
        <HudPanel>
          <Notice tone="warning">无法加载账号门户。{state.message}
            <button type="button" className="chenxing-link ml-2" onClick={() => void load()}>重试</button>
          </Notice>
        </HudPanel>
      ) : null}
      {state.kind === 'ready' && available.length ? (
        <HudPanel as="section" className="mb-4 !p-5 sm:!p-6" aria-label="可绑定提供方">
          <div className="space-y-4">
            {available.map((provider) => (
              <div key={provider.id} className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="chenxing-h3">{provider.display_name}</h2>
                  <p className="chenxing-caption mt-1 chenxing-mono">{provider.issuer}</p>
                </div>
                <Button icon="link" disabled={mutationLock.busy} onClick={() => { setDialogError(null); setDialog({ kind: 'bind', provider }) }}>
                  绑定
                </Button>
              </div>
            ))}
          </div>
        </HudPanel>
      ) : null}
      {state.kind === 'ready' && bindings.length === 0 && available.length === 0 ? (
        <HudPanel>
          <EmptyState icon="fingerprint" title="暂无账号门户绑定" description="管理员启用提供方后，绑定入口会出现在这里。" />
        </HudPanel>
      ) : null}
      {bindings.length ? (
        <div className="space-y-4">
          {bindings.map((binding) => {
            const name = providerName(binding.provider_id, binding.issuer)
            const title = binding.name || binding.account || binding.uid || name
            return (
              <HudPanel key={binding.id} as="article" className="!p-5 sm:!p-6">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h2 className="chenxing-h3">{name}</h2>
                      <Badge tone={binding.status && binding.status !== 'active' ? 'warning' : 'success'}>
                        {binding.status || '已绑定'}
                      </Badge>
                    </div>
                    <p className="chenxing-caption mt-1">{title}</p>
                    <p className="chenxing-caption chenxing-mono mt-1">{binding.uid || binding.issuer}</p>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="ghost" icon="refresh-cw" disabled={mutationLock.busy || pendingId === binding.id} onClick={() => void runBindingAction(binding, 'sync')}>
                      {pendingId === binding.id ? '同步中…' : '同步'}
                    </Button>
                    <Button variant="ghost" disabled={mutationLock.busy || pendingId === binding.id} onClick={() => void runBindingAction(binding, 'refresh')}>刷新令牌</Button>
                    <Button variant="danger" icon="unlink" disabled={mutationLock.busy} onClick={() => { setDialogError(null); setDialog({ kind: 'unlink', binding }) }}>解绑</Button>
                  </div>
                </div>
                <dl className="mt-5 grid grid-cols-1 gap-4 border-t border-[var(--chenxing-border)] pt-5 sm:grid-cols-2">
                  <div><dt className="chenxing-caption">账号</dt><dd className="chenxing-body">{binding.account || '—'}</dd></div>
                  <div><dt className="chenxing-caption">授权到期</dt><dd className="chenxing-body">{formatDate(binding.grant_expires_at)}</dd></div>
                </dl>
              </HudPanel>
            )
          })}
        </div>
      ) : null}
      {dialog?.kind === 'bind' ? (
        <BindPortalDialog provider={dialog.provider} busy={mutationLock.busy} error={dialogError} onCancel={() => setDialog(null)} onSubmit={(identifier, secret) => bind(dialog.provider, identifier, secret)} />
      ) : null}
      {dialog?.kind === 'unlink' ? (
        <UnlinkPortalDialog name={providerName(dialog.binding.provider_id, dialog.binding.issuer)} busy={mutationLock.busy} error={dialogError} onCancel={() => setDialog(null)} onSubmit={() => runBindingAction(dialog.binding, 'unlink')} />
      ) : null}
    </ConsoleLayout>
  )
}
