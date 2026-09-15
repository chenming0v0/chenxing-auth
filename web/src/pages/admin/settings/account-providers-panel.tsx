import { useState } from 'react'
import { Badge, Button, DataTable, EmptyState, Notice, RowAction, RowActions, TablePanel } from '@chenxing/ui'
import { apiFetch } from '../../../api'
import type { AccountProviderUpdate, ManagedAccountProvider } from '../../../account-provider-types'
import { useMutationLock } from '../../../use-mutation-lock'
import { AccountProviderForm } from './account-provider-form'
import { useSettingsResource, type SettingsPanelProps } from './panel'

const PATH = '/api/v1/admin/account-providers'

export function AccountProvidersPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [providers, setProviders] = useState<ManagedAccountProvider[] | null>(null)
  const [editing, setEditing] = useState<ManagedAccountProvider | null>(null)
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const { busy, run } = useMutationLock()
  const { loading, failed, reload } = useSettingsResource<ManagedAccountProvider[]>({
    path: PATH, onMessage, failureMessage: '特殊供应商加载失败。', apply: setProviders,
  })
  function show(provider: ManagedAccountProvider | null) {
    setEditing(provider); setError(''); setOpen(true)
  }
  async function save(input: AccountProviderUpdate) {
    await run(async () => {
      try {
        await apiFetch(`${PATH}/${encodeURIComponent(input.slug)}`, { method: 'PUT', body: JSON.stringify(input) })
        setOpen(false); setError('')
        onMessage('特殊供应商已保存。')
        await reload()
      } catch (reason) { setError(reason instanceof Error ? reason.message : '保存失败。') }
    })
  }
  async function toggle(provider: ManagedAccountProvider) {
    if (!window.confirm(`确认${provider.enabled ? '停用' : '启用'} ${provider.name}？`)) return
    await run(async () => {
      try {
        const { slug, name, adapter, base_url, allowed_client_ids, version } = provider
        await apiFetch(`${PATH}/${encodeURIComponent(slug)}`, {
          method: 'PUT',
          body: JSON.stringify({ slug, name, adapter, base_url, allowed_client_ids, enabled: !provider.enabled, expected_version: version }),
        })
        onMessage(provider.enabled ? '供应商已停用，已有绑定保留。' : '供应商已启用。')
        await reload()
      } catch (reason) {
        onMessage(reason instanceof Error ? reason.message : '供应商状态更新失败。', 'warning')
        await reload()
      }
    })
  }
  return (
    <>
      <TablePanel icon="terminal" title="特殊供应商"
        action={<Button icon="plus" disabled={busy || loading || failed} onClick={() => show(null)}>添加特殊供应商</Button>}
        notice={failed ? <Notice tone="warning">特殊供应商加载失败。<Button variant="ghost" icon="refresh-cw" onClick={() => void reload()}>重试</Button></Notice> : undefined}>
        <DataTable minWidth={800} columns={['名称 / 标识', '类型', '服务地址', 'OAuth Client ID', '状态', { label: '操作', align: 'right' }]}
          empty={loading && !providers ? '正在加载特殊供应商。' : failed && !providers ? '暂时无法读取配置。' : providers?.length ? null :
            <EmptyState icon="terminal" title="尚未配置特殊供应商" />}>
          {providers?.map((provider) => (
            <tr key={provider.slug}>
              <td><span>{provider.name}</span><p className="chenxing-caption">{provider.slug}</p></td>
              <td>CLtermux</td>
              <td className="break-all max-w-xs">{provider.base_url}</td>
              <td className="break-all max-w-xs">{provider.allowed_client_ids.join(', ')}</td>
              <td><Badge tone={provider.enabled ? 'success' : 'warning'}>{provider.enabled ? '已启用' : '已停用'}</Badge></td>
              <RowActions>
                <RowAction disabled={busy || loading || failed} onClick={() => show(provider)}>编辑</RowAction>
                <RowAction disabled={busy || loading || failed} tone={provider.enabled ? 'danger' : 'default'}
                  onClick={() => void toggle(provider)}>{provider.enabled ? '停用' : '启用'}</RowAction>
              </RowActions>
            </tr>
          ))}
        </DataTable>
      </TablePanel>
      {open ? <AccountProviderForm key={editing?.slug ?? 'new'} editing={editing} busy={busy} error={error}
        onSave={(value) => void save(value)} onClose={() => setOpen(false)} onDirtyChange={onDirtyChange} /> : null}
    </>
  )
}
