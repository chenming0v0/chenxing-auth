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

export const statItems = [
  { label: '活跃会话', value: '02', hint: '近 30 天', icon: 'radio-tower', tone: 'cyan' },
  { label: '已授权应用', value: '04', hint: '全部正常', icon: 'shield-check', tone: 'green' },
  { label: '当前套餐', value: 'FREE', hint: '基础权益', icon: 'orbit', tone: 'gold' },
] as const

export const plans = [
  { name: '星尘', price: '免费', code: 'FREE', description: '适合个人项目和早期验证。', features: ['3 个 OAuth 应用', '每月 10,000 次认证', '标准登录方式'], current: true },
  { name: '星轨', price: '¥49 / 月', code: 'ORBIT', description: '为持续增长的产品提供更高配额。', features: ['20 个 OAuth 应用', '每月 200,000 次认证', '品牌化登录页'], current: false },
  { name: '天穹', price: '联系销售', code: 'SKY', description: '企业级安全策略和专属支持。', features: ['无限 OAuth 应用', '自定义策略与审计', '专属技术支持'], current: false },
] as const

export const users = [
  { name: '林默', email: 'lin.mo@example.com', status: '正常', role: 'Owner', joined: '2026-07-30', lastSeen: '刚刚' },
  { name: '苏棠', email: 'su.tang@example.com', status: '正常', role: 'Member', joined: '2026-07-29', lastSeen: '12 分钟前' },
  { name: '周屿', email: 'zhou.yu@example.com', status: '已暂停', role: 'Member', joined: '2026-07-24', lastSeen: '3 天前' },
  { name: '夏目', email: 'natsu@example.com', status: '正常', role: 'Member', joined: '2026-07-18', lastSeen: '昨天' },
] as const

export const apps = [
  { name: '星图工作台', clientId: 'cli_xingtu_7a18', redirect: 'https://xingtu.example.com/callback', scopes: ['openid', 'profile', 'email'], status: '已启用', created: '2026-07-29' },
  { name: '辰星文档', clientId: 'cli_docs_24be', redirect: 'https://docs.example.com/auth/callback', scopes: ['openid', 'profile'], status: '已启用', created: '2026-07-21' },
  { name: '本地 Playground', clientId: 'cli_local_5f2d', redirect: 'http://localhost:5175/oauth/callback', scopes: ['openid'], status: '测试中', created: '2026-07-15' },
] as const
