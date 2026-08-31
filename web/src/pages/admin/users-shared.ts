import type { PublicUser } from '../../api'
import type { SelectOption } from '@chenxing/ui'

export const ROLE_OPTIONS: SelectOption[] = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
  { value: 'owner', label: 'Owner' },
]

const ROLE_LABEL: Record<string, string> = {
  user: '普通用户',
  admin: '管理员',
  owner: 'Owner',
}

export const STATUS_FILTER_OPTIONS: SelectOption[] = [
  { value: '', label: '全部状态' },
  { value: 'active', label: '已启用' },
  { value: 'disabled', label: '已禁用' },
]

export const STATUS_LABEL: Record<string, string> = {
  active: '已启用',
  disabled: '已禁用',
}

/** 角色变更的确认文案：点明变更方向，并在涉及 Owner 时说明其全部管理权限的后果。 */
export function roleChangeConfirmText(user: PublicUser, nextRole: string): string {
  const name = user.display_name || user.username
  const current = ROLE_LABEL[user.role] ?? user.role
  const next = ROLE_LABEL[nextRole] ?? nextRole

  let consequence: string
  if (nextRole === 'owner') {
    consequence = '提升为 Owner 后将拥有全部管理权限（用户、套餐、密钥轮换、审计与 OAuth 客户端），并可管理其他管理员与 Owner。'
  } else if (nextRole === 'admin' && user.role === 'user') {
    consequence = '提升为管理员后将获得用户、Client、审计与邀请码/兑换码等运营管理权限，也可为用户分配现有套餐；系统设置、身份提供商、套餐定义和密钥仍由 Owner 管理。'
  } else if (nextRole === 'admin') {
    consequence = '降级为管理员后将移除 Owner 独有的权限（系统设置、身份提供商、套餐定义、密钥轮换及管理其他管理员与 Owner），保留用户、Client、审计、运营管理和分配现有套餐权限。'
  } else if (user.role === 'owner') {
    consequence = '降级为普通用户将立即移除 Owner 的全部管理权限（用户、套餐、密钥轮换、审计与 OAuth 客户端），仅保留普通用户权限。'
  } else {
    consequence = '降级为普通用户将移除其全部后台管理权限。'
  }
  return `确认将 ${name} 的角色从「${current}」改为「${next}」？\n${consequence}`
}
