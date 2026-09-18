import { useState } from 'react'
import { Badge, Button, DataTable, EmptyState, Notice, RowAction, RowActions, TablePanel } from '@chenxing/ui'
import {
  createResourceServiceAdminProvider,
  listResourceServiceAdminProviders,
  setResourceServiceAdminProviderEnabled,
  updateResourceServiceAdminProvider,
} from '../../../resource-services-api'
import type { ResourceServiceAdminProvider, ResourceServiceProviderInput } from '../../../resource-services-types'
import { useMutationLock } from '../../../use-mutation-lock'
import { ResourceServiceForm, scopeAccessLabel } from './resource-services-form'
import { useSettingsResource, type SettingsPanelProps } from './panel'

const PATH = '/api/v1/admin/resource-services'

export function ResourceServicesPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [providers, setProviders] = useState<ResourceServiceAdminProvider[] | null>(null)
  const [editing, setEditing] = useState<ResourceServiceAdminProvider | null>(null)
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const { busy, run } = useMutationLock()
  const { loading, failed, reload } = useSettingsResource<ResourceServiceAdminProvider[]>({
    path: PATH, onMessage, failureMessage: '资源服务加载失败。', apply: setProviders,
  })

  function show(provider: ResourceServiceAdminProvider | null) {
    setEditing(provider)
    setError('')
    setOpen(true)
  }

  async function save(input: ResourceServiceProviderInput) {
    await run(async () => {
      try {
        if (editing) await updateResourceServiceAdminProvider(editing.id, input)
        else await createResourceServiceAdminProvider(input)
        setOpen(false)
        setError('')
        onMessage('资源服务已保存。')
        await reload()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : '保存失败。')
      }
    })
  }

  async function toggle(provider: ResourceServiceAdminProvider) {
    if (!window.confirm(`确认${provider.enabled ? '停用' : '启用'} ${provider.display_name}？`)) return
    await run(async () => {
      try {
        await setResourceServiceAdminProviderEnabled(provider.id, !provider.enabled)
        onMessage(provider.enabled ? '资源服务已停用，已有绑定保留。' : '资源服务已启用。')
        await reload()
      } catch (reason) {
        onMessage(reason instanceof Error ? reason.message : '状态更新失败。', 'warning')
        await reload()
      }
    })
  }

  return (
    <>
      <TablePanel icon="fingerprint" title="资源服务"
        action={<Button icon="plus" disabled={busy || loading || failed} onClick={() => show(null)}>添加资源服务</Button>}
        notice={failed ? <Notice tone="warning">资源服务加载失败。<Button variant="ghost" icon="refresh-cw" onClick={() => void reload()}>重试</Button></Notice> : undefined}>
        <DataTable minWidth={960} columns={['名称', 'Issuer', 'Client ID', '权限', '开放范围', '状态', { label: '操作', align: 'right' }]}
          empty={loading && !providers ? '正在加载资源服务。' : failed && !providers ? '暂时无法读取配置。' : providers?.length ? null :
            <EmptyState icon="fingerprint" title="尚未配置资源服务" />}>
          {providers?.map((provider) => (
            <tr key={provider.id}>
              <td>
                <span>{provider.display_name}</span>
                <p className="chenxing-caption chenxing-mono">{provider.slug}</p>
                {provider.identity_locked ? <p className="chenxing-caption">身份已锁定</p> : null}
              </td>
              <td className="break-all max-w-xs">{provider.issuer}</td>
              <td className="break-all max-w-xs">{provider.client_id}</td>
              <td className="break-all max-w-xs chenxing-mono">{provider.scope}</td>
              <td>
                <span>{scopeAccessLabel(provider.scope_access)}</span>
                {provider.scope_access === 'restricted' ? (
                  <p className="chenxing-caption">{provider.allowed_client_ids.length} 个应用</p>
                ) : null}
              </td>
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
      {open ? (
        <ResourceServiceForm key={editing?.id ?? 'new'} editing={editing} busy={busy} error={error}
          onSave={(value) => void save(value)} onClose={() => setOpen(false)} onDirtyChange={onDirtyChange} />
      ) : null}
    </>
  )
}
