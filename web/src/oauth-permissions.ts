export type OAuthPermission = {
  scope: string
  title: string
  desc: string
}

const PERMISSIONS: Record<string, Omit<OAuthPermission, 'scope'>> = {
  openid: { title: '身份标识', desc: '获取你的唯一辰星 ID，用于识别账户身份' },
  profile: { title: '基本资料', desc: '查看你的昵称、头像与公开个人信息' },
  email: { title: '电子邮箱', desc: '读取与你账号关联的邮箱地址' },
  offline_access: { title: '离线访问', desc: '在你离线时刷新访问令牌' },
}

/** 注册抽屉展示的默认 allowlist，不含 offline_access。 */
export const DEFAULT_OAUTH_SCOPES = ['openid', 'profile', 'email'] as const

/** 新建应用时预勾选默认 allowlist 三项。 */
export const DEFAULT_SELECTED_SCOPES: string[] = ['openid', 'profile', 'email']

export function permissionMeta(scope: string): OAuthPermission {
  const known = PERMISSIONS[scope]
  if (known) return { scope, title: known.title, desc: known.desc }
  return { scope, title: scope, desc: '应用请求的额外权限范围' }
}

/** 默认 allowlist，再加上当前已选、但不在目录里的 scope，避免编辑时悄悄丢掉自定义项。 */
export function permissionChoices(selected: readonly string[]): OAuthPermission[] {
  const catalog = DEFAULT_OAUTH_SCOPES.map(permissionMeta)
  const catalogSet = new Set<string>(DEFAULT_OAUTH_SCOPES)
  const extras: OAuthPermission[] = []
  const seen = new Set<string>()
  for (const scope of selected) {
    if (catalogSet.has(scope) || seen.has(scope)) continue
    seen.add(scope)
    extras.push(permissionMeta(scope))
  }
  return [...catalog, ...extras]
}
