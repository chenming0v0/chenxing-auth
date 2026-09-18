import { useState } from 'react'
import { Badge, Button, DataTable, EmptyState, Notice, RowAction, RowActions, TablePanel } from '@chenxing/ui'
import {
  createAccountPortalAdminProvider,
  listAccountPortalAdminProviders,
  setAccountPortalAdminProviderEnabled,
  updateAccountPortalAdminProvider,
} from '../../../account-portal-api'
import type { AccountPortalAdminProvider, AccountPortalProviderInput } from '../../../account-portal-types'
import { useMutationLock } from '../../../use-mutation-lock'
import { AccountPortalForm } from './account-portal-form'
import { useSettingsResource, type SettingsPanelProps } from './panel'

const PATH = '/api/v1/admin/account-portal/providers'

export function AccountPortalPanel({ onMessage, onDirtyChange }: SettingsPanelProps) {
  const [providers, setProviders] = useState<AccountPortalAdminProvider[] | null>(null)
  const [editing, setEditing] = useState<AccountPortalAdminProvider | null>(null)
  const [open, setOpen] = useState(false)
  const [error, setError] = useState('')
  const { busy, run } = useMutationLock()
  const { loading, failed, reload } = useSettingsResource<AccountPortalAdminProvider[]>({
    path: PATH, onMessage, failureMessage: '账号门户提供方加载失败。', apply: setProviders,
  })

  function show(provider: AccountPortalAdminProvider | null) {
    setEditing(provider)
    setError('')
    setOpen(true)
  }

  async function save(input: AccountPortalProviderInput) {
    await run(async () => {
      try {
        if (editing) await updateAccountPortalAdminProvider(editing.id, input)
        else await createAccountPortalAdminProvider(input)
        setOpen(false)
        setError('')
        onMessage('账号门户提供方已保存。')
        await reload()
      } catch (reason) {
        setError(reason instanceof Error ? reason.message : '保存失败。')
      }
    })
  }

  async function toggle(provider: AccountPortalAdminProvider) {
    if (!window.confirm(`确认${provider.enabled ? '停用' : '启用'} ${provider.display_name}？`)) return
    await run(async () => {
      try {
        await setAccountPortalAdminProviderEnabled(provider.id, !provider.enabled)
        onMessage(provider.enabled ? '提供方已停用，已有绑定保留。' : '提供方已启用。')
        await reload()
      } catch (reason) {
        onMessage(reason instanceof Error ? reason.message : '状态更新失败。', 'warning')
        await reload()
      }
    })
  }

  return (
    <>
      <TablePanel icon="fingerprint" title="账号门户提供方"
        action={<Button icon="plus" disabled={busy || loading || failed} onClick={() => show(null)}>添加账号门户提供方</Button>}
        notice={failed ? <Notice tone="warning">账号门户提供方加载失败。<Button variant="ghost" icon="refresh-cw" onClick={() => void reload()}>重试</Button></Notice> : undefined}>
        <DataTable minWidth={800} columns={['名称', 'Issuer', 'Client ID', '状态', { label: '操作', align: 'right' }]}
          empty={loading && !providers ? '正在加载账号门户提供方。' : failed && !providers ? '暂时无法读取配置。' : providers?.length ? null :
            <EmptyState icon="fingerprint" title="尚未配置账号门户提供方" />}>
          {providers?.map((provider) => (
            <tr key={provider.id}>
              <td>
                <span>{provider.display_name}</span>
                {provider.identity_locked ? <p className="chenxing-caption">身份已锁定</p> : null}
              </td>
              <td className="break-all max-w-xs">{provider.issuer}</td>
              <td className="break-all max-w-xs">{provider.client_id}</td>
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
        <AccountPortalForm key={editing?.id ?? 'new'} editing={editing} busy={busy} error={error}
          onSave={(value) => void save(value)} onClose={() => setOpen(false)} onDirtyChange={onDirtyChange} />
      ) : null}
    </>
  )
}

