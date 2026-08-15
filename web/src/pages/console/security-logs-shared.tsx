import { Badge } from '../../components/ui'

export const PAGE_SIZE = 20

/** 已知 action 的友好文案与语气；未知 action 原样以等宽字体展示，不做猜测。
    等级/类别体系的正式化（服务端返回 severity/category）见 issue #308。 */
export const ACTION_PRESENTATION: Record<string, { label: string; tone: 'success' | 'warning' | 'neutral' }> = {
  login: { label: '登录', tone: 'success' },
  login_failed: { label: '登录失败', tone: 'warning' },
  session_revoke: { label: '撤销会话', tone: 'warning' },
  password_change: { label: '修改密码', tone: 'neutral' },
  user_avatar_update: { label: '更新头像', tone: 'neutral' },
  user_avatar_remove: { label: '移除头像', tone: 'neutral' },
  oauth_consent: { label: '授权应用', tone: 'success' },
  oauth_consent_revoke: { label: '撤销授权', tone: 'warning' },
}

export function ActionBadge({ action }: { action: string }) {
  const known = ACTION_PRESENTATION[action]
  if (!known) return <span className="chenxing-mono text-sm">{action || '—'}</span>
  return <Badge tone={known.tone}>{known.label}</Badge>
}
