import { Badge } from '../../components/ui'
import type { Paged, SecurityEvent, SecurityEventDetail } from '../../api'

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

/* ---------- 示例数据 ----------
   仅在接口 404（尚未实现，#307/#308）时用于预览页面形态；
   后端就绪后 404 消失，以下内容自动退场。 */

const PREVIEW_CLIENTS: [string, string][] = [
  ['cx_wong_backup', 'WONG 公益站备用'],
  ['cx_jige_ai', '鸡哥 AI'],
  ['cx_maoyulin', '猫羽霖 API'],
  ['cx_fastmodel', 'fastmodel'],
  ['cx_allrouter', 'All Router'],
]

export function buildPreviewEvents(): SecurityEvent[] {
  const base = Date.parse('2026-08-12T17:13:23Z')
  const actions: { action: string; resource_type: string | null; withClient: boolean }[] = [
    { action: 'oauth_consent', resource_type: 'client', withClient: true },
    { action: 'login', resource_type: 'session', withClient: false },
    { action: 'oauth_consent', resource_type: 'client', withClient: true },
    { action: 'session_revoke', resource_type: 'session', withClient: false },
    { action: 'user_avatar_update', resource_type: 'user', withClient: false },
    { action: 'oauth_consent_revoke', resource_type: 'client', withClient: true },
    { action: 'login_failed', resource_type: 'session', withClient: false },
    { action: 'password_change', resource_type: 'user', withClient: false },
  ]
  return Array.from({ length: 47 }, (_, index) => {
    const spec = actions[index % actions.length]
    const [client_id, client_name] = spec.withClient
      ? PREVIEW_CLIENTS[index % PREVIEW_CLIENTS.length]
      : [null, null]
    return {
      id: 11045978 - index,
      action: spec.action,
      resource_type: spec.resource_type,
      client_id,
      client_name,
      /* 间隔递增的伪时间轴：近的按小时、远的按天回退 */
      created_at: new Date(base - index * 5.37e6 - index * index * 6.1e5).toISOString(),
    }
  })
}

export function previewPage(page: number): Paged<SecurityEvent> {
  const events = buildPreviewEvents()
  return {
    items: events.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    page,
    page_size: PAGE_SIZE,
    total: events.length,
  }
}

export function previewDetail(id: number): SecurityEventDetail | null {
  const event = buildPreviewEvents().find((item) => item.id === id)
  if (!event) return null
  const hasSession = event.resource_type === 'session'
  return {
    ...event,
    category: event.action.startsWith('oauth') ? 'authorization' : hasSession ? 'auth' : 'account',
    severity: ACTION_PRESENTATION[event.action]?.tone === 'warning' ? 'warning' : 'notice',
    ip: `203.0.113.${(id % 200) + 1}`,
    ip_location: ['US', 'DE', 'SG', 'MY', 'JP'][id % 5],
    user_agent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0 Safari/537.36',
    ray_id: `cx${id.toString(16)}f3a9${(id * 7).toString(16)}`,
    client: event.client_id && event.client_name
      ? { client_id: event.client_id, client_name: event.client_name, created_at: '2025-12-20T11:55:31Z', status: 'active' }
      : null,
  }
}
