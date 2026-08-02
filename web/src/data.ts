type NavItem = { label: string; path: string; icon: string }
type NavGroup = { label: string; items: NavItem[] }

export const navGroups: NavGroup[] = [
  {
    label: '账户',
    items: [
      { label: '总览', path: '/console', icon: 'layout-grid' },
      { label: '套餐与权益', path: '/console/plans', icon: 'crown' },
      { label: '个人信息', path: '/console/profile', icon: 'user' },
      { label: '已授权应用', path: '/console/apps', icon: 'shield-check' },
    ],
  },
  {
    label: '开发者',
    items: [
      { label: '接入应用', path: '/console/integrate', icon: 'code-2' },
      { label: '授权测试', path: '/console/playground', icon: 'flask-conical' },
    ],
  },
  {
    label: '管理',
    items: [
      { label: '仪表盘', path: '/admin', icon: 'gauge' },
      { label: '用户管理', path: '/admin/users', icon: 'users' },
    ],
  },
  {
    label: '系统',
    items: [{ label: '系统设置', path: '/admin/settings', icon: 'settings' }],
  },
]
