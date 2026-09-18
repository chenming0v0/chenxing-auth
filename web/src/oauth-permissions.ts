export type OAuthPermission = {
  scope: string
  title: string
  desc: string
  /** 来自资源服务的 scope 在清单里带「资源服务」标记；基础 scope 与未知 scope 为 undefined。 */
  source?: 'base' | 'resource_service'
}

/** GET /api/v1/auth/oauth-scopes 的条目：基础 scope 与已启用资源服务声明的 scope。 */
export type ScopeCatalogItem = {
  scope: string
  title: string
  description: string
  source: 'base' | 'resource_service'
  access: 'restricted' | 'public' | null
  provider_slug: string | null
}

export type ScopeCatalogResponse = { items: ScopeCatalogItem[] }

/** 离线兜底文案：目录接口不可用时仍能渲染基础 scope，与服务端固定文案保持一致。 */
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

/** 把目录之外、但当前已选的 scope 补到末尾，避免编辑时悄悄丢掉自定义项。 */
function withSelectedExtras(catalog: OAuthPermission[], selected: readonly string[]): OAuthPermission[] {
  const seen = new Set(catalog.map((item) => item.scope))
  const extras: OAuthPermission[] = []
  for (const scope of selected) {
    if (seen.has(scope)) continue
    seen.add(scope)
    extras.push(permissionMeta(scope))
  }
  return [...catalog, ...extras]
}

/** 离线兜底：默认 allowlist 加当前已选项。 */
export function permissionChoices(selected: readonly string[]): OAuthPermission[] {
  return withSelectedExtras(DEFAULT_OAUTH_SCOPES.map(permissionMeta), selected)
}

/** 服务端目录优先：标题与说明以目录为准，资源服务条目保留来源标记。 */
export function catalogPermissionChoices(
  items: readonly ScopeCatalogItem[],
  selected: readonly string[],
): OAuthPermission[] {
  const catalog = items.map((item) => ({
    scope: item.scope,
    title: item.title,
    desc: item.description,
    source: item.source,
  }))
  return withSelectedExtras(catalog, selected)
}
