import { useEffect, useState, type ReactNode } from 'react'
import { apiFetch, type AdminMeResponse } from '../../api'
import { HudPanel, Notice } from '@chenxing/ui'

export type AdminAccess = { data: AdminMeResponse | null; loading: boolean; error: string }

export function parsePageParam(value: string | null): number {
  const page = Number(value)
  return Number.isFinite(page) && Number.isInteger(page) && page >= 1 ? page : 1
}

/** 表格分页的每页条数：URL 里的 page_size 只接受这几档，其余一律回落默认值 */
export const PAGE_SIZE_OPTIONS = [10, 20, 50, 100] as const
export const DEFAULT_PAGE_SIZE = 20

export function parsePageSizeParam(value: string | null): number {
  const size = Number(value)
  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(size) ? size : DEFAULT_PAGE_SIZE
}

export function useAdminAccess(): AdminAccess {
  const [data, setData] = useState<AdminMeResponse | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    let active = true
    void apiFetch<AdminMeResponse>('/api/v1/admin/auth/me')
      .then((value) => { if (active) setData(value) })
      .catch((reason: unknown) => { if (active) setError(reason instanceof Error ? reason.message : '管理身份加载失败。') })
      .finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [])
  return { data, error, loading }
}

export function AdminGate({ access, permission, children }: { access: AdminAccess; permission?: string; children: ReactNode }) {
  if (access.loading) return <HudPanel><Notice>正在检查管理身份和权限。</Notice></HudPanel>
  if (access.error || !access.data) return <HudPanel><Notice tone="warning">{access.error || '当前会话不是有效的管理员会话。'}</Notice></HudPanel>
  if (permission && !access.data.permissions.includes(permission)) {
    return <HudPanel><Notice tone="warning">当前管理身份没有 `{permission}` 权限，服务端数据不会在此页面展示。</Notice></HudPanel>
  }
  return <>{children}</>
}
