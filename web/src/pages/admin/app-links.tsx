import { useEffect, useState } from 'react'
import { apiFetch, type AppLinkResponse } from '../../api'
import { ConsoleLayout } from '../../components/shells'
import { Button, EmptyState, Notice, PageIntro } from '@chenxing/ui'
import { DataTable, RowAction, RowActions, TablePanel } from '@chenxing/ui'
import { AdminGate, useAdminAccess, type AdminAccess } from './shared'
import { AppLinkDrawer } from './app-link-drawer'

export function AdminAppLinks() {
  const access = useAdminAccess()
  return (
    <ConsoleLayout>
      <PageIntro
        eyebrow="// Admin · App Links"
        title="软件链接"
        description="登记 Android 包名和签名指纹。辰星在 /.well-known/assetlinks.json 公开发布，供系统把 /app/<数字ID>/oauth/callback 交给对应 App。"
      />
      <AdminGate access={access} permission="manage_clients">
        <AppLinksWorkspace />
      </AdminGate>
    </ConsoleLayout>
  )
}

export function AppLinksWorkspace(_props: { access?: AdminAccess } = {}) {
  const [items, setItems] = useState<AppLinkResponse[] | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [refreshKey, setRefreshKey] = useState(0)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [editingItem, setEditingItem] = useState<AppLinkResponse | null>(null)

  useEffect(() => {
    let active = true
    void apiFetch<AppLinkResponse[]>('/api/v1/admin/app-links')
      .then((value) => {
        if (!active) return
        setItems(value)
        setError('')
      })
      .catch((reason: unknown) => {
        if (active) {
          setItems(null)
          setError(reason instanceof Error ? reason.message : '软件链接加载失败。')
        }
      })
    return () => { active = false }
  }, [refreshKey])

  function openCreate() {
    setEditingItem(null)
    setDrawerOpen(true)
  }

  function openEdit(item: AppLinkResponse) {
    setEditingItem(item)
    setDrawerOpen(true)
  }

  function closeDrawer() {
    setDrawerOpen(false)
    setEditingItem(null)
  }

  async function remove(item: AppLinkResponse) {
    if (busy) return
    if (!window.confirm(`确认清除 ${item.client_name} 的软件链接吗？\n清除后 Android 将不再把回调交给该 App。`)) return
    setBusy(true)
    setError('')
    try {
      await apiFetch<void>(`/api/v1/admin/app-links/${encodeURIComponent(item.client_id)}`, { method: 'DELETE' })
      setRefreshKey((value) => value + 1)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '软件链接清除失败。')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <TablePanel
        icon="smartphone"
        title="已登记软件"
        action={<Button icon="plus" onClick={openCreate}>登记软件</Button>}
        notice={error ? <Notice tone="warning">{error}</Notice> : null}
      >
        <DataTable
          minWidth={920}
          columns={['软件', 'App ID', '包名', '指纹', { label: '操作', align: 'right' }]}
          empty={items?.length ? null : items ? (
            <EmptyState icon="smartphone" title="还没有软件链接" description="点「登记软件」，填入包名和签名指纹。认证链接在「认证链接」页单独配置。" />
          ) : error ? null : '正在加载软件链接。'}
        >
          {items?.map((item) => (
            <tr key={item.client_id}>
              <td>
                <p className="chenxing-body text-sm font-semibold">{item.client_name}</p>
                <p className="chenxing-mono text-xs text-[var(--chenxing-muted-foreground)]">{item.client_id}</p>
              </td>
              <td className="chenxing-mono text-sm">{item.numeric_app_id}</td>
              <td className="chenxing-mono text-xs">{item.package_name}</td>
              <td className="chenxing-caption">{item.sha256_cert_fingerprints.length} 条 · /app/{item.numeric_app_id}/oauth/callback</td>
              <RowActions>
                <RowAction onClick={() => openEdit(item)} disabled={busy}>编辑</RowAction>
                <RowAction tone="danger" onClick={() => void remove(item)} disabled={busy}>清除</RowAction>
              </RowActions>
            </tr>
          ))}
        </DataTable>
      </TablePanel>
      {drawerOpen ? (
        <AppLinkDrawer
          editing={editingItem}
          onClose={closeDrawer}
          onSaved={() => {
            closeDrawer()
            setRefreshKey((value) => value + 1)
          }}
        />
      ) : null}
    </div>
  )
}
