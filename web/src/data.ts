export type NavItem = { label: string; path: string; icon: string }
export type NavGroup = { label: string; items: NavItem[] }

export const navGroups: NavGroup[] = [
  {
    label: '账户',
    items: [
      { label: '总览', path: '/console', icon: 'layout-grid' },
      { label: '个人信息', path: '/console/profile', icon: 'user' },
      { label: '钱包', path: '/console/wallet', icon: 'wallet' },
      { label: '已授权应用', path: '/console/apps', icon: 'shield-check' },
      { label: '安全日志', path: '/console/logs', icon: 'activity' },
    ],
  },
  {
    label: '开发者',
    items: [
      { label: '接入应用', path: '/console/integrate', icon: 'code-2' },
      { label: '授权测试', path: '/console/playground', icon: 'flask-conical' },
      { label: '套餐与权益', path: '/console/plans', icon: 'crown' },
    ],
  },
  {
    label: '管理',
    items: [
      { label: '仪表盘', path: '/admin', icon: 'gauge' },
      { label: '用户管理', path: '/admin/users', icon: 'users' },
      { label: 'Client 管理', path: '/admin/clients', icon: 'key-round' },
      { label: '审计日志', path: '/admin/audit', icon: 'file-search' },
      { label: '套餐管理', path: '/admin/plans', icon: 'crown' },
      { label: '邀请码', path: '/admin/invitations', icon: 'ticket' },
    ],
  },
  {
    label: '系统',
    items: [
      { label: '身份提供商', path: '/admin/oauth-providers', icon: 'link' },
      { label: '系统设置', path: '/admin/settings', icon: 'settings' },
    ],
  },
]

export const pageStatus: Record<string, string> = {
  '/': '认证中枢',
  '/login': '统一登录',
  '/register': '创建通行证',
  '/bootstrap': '系统初始化',
  '/oauth/account': 'OAuth · 选择账号',
  '/oauth/consent': 'OAuth · 授权确认',
  '/oauth/redirect': 'OAuth · 回调',
  '/console': '控制台 · 总览',
  '/console/plans': '控制台 · 套餐与权益',
  '/console/profile': '控制台 · 个人信息',
  '/console/wallet': '控制台 · 钱包',
  '/console/security': '控制台 · 个人信息',
  '/settings/security': '控制台 · 个人信息',
  '/console/apps': '控制台 · 已授权应用',
  '/console/logs': '控制台 · 安全日志',
  '/console/integrate': '控制台 · 接入应用',
  '/console/playground': '控制台 · 授权测试',
  '/admin': '管理 · 仪表盘',
  '/admin/users': '管理 · 用户管理',
  '/admin/plans': '管理 · 套餐管理',
  '/admin/clients': '管理 · 客户端',
  '/admin/audit': '管理 · 审计日志',
  '/admin/invitations': '管理 · 邀请码',
  '/admin/oauth-providers': '管理 · 身份提供商',
  '/admin/settings': '管理 · 系统设置',
}

export const DEFAULT_DOCUMENT_TITLE = '辰星通行证 · 天穹辰星'

export function getDocumentTitle(pathname: string): string {
  const status = pageStatus[pathname]
  return pathname === '/' || !status ? DEFAULT_DOCUMENT_TITLE : `${status} · 辰星通行证`
}

export function formatDate(value?: string | null): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.valueOf())
    ? '—'
    : date.toLocaleString('zh-CN', { dateStyle: 'medium', timeStyle: 'short' })
}

export function greeting(): string {
  const hour = new Date().getHours()
  if (hour < 6) return '夜深了'
  if (hour < 12) return '上午好'
  if (hour < 18) return '午安'
  return '晚上好'
}

export function initialOf(name?: string | null): string {
  const value = (name || '辰').trim()
  return value.slice(0, 1).toUpperCase()
}
