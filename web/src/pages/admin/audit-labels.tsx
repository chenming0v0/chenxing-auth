import { Badge } from '../../components/ui'
import type { SelectOption } from '../../components/select'

/** 与 `src/audit/classification.rs` 的 SecurityEventSeverity 对齐。 */
export type AuditSeverity = 'info' | 'notice' | 'warning' | 'critical'

type ActionInfo = { label: string; severity: AuditSeverity }

/**
 * 管理端审计动作目录。未知历史值不进这张表，界面必须原样展示 snake_case，
 * 不能猜中文名。严重级别与 classification.rs 保持一致。
 */
export const ACTION_CATALOG: Record<string, ActionInfo> = {
  login: { label: '登录', severity: 'notice' },
  login_failure: { label: '登录失败', severity: 'warning' },
  login_failed: { label: '登录失败', severity: 'warning' },
  login_rate_limited: { label: '登录频率限制', severity: 'warning' },
  mfa_failure: { label: '多因素验证失败', severity: 'warning' },
  rate_limit_triggered: { label: '触发频率限制', severity: 'warning' },
  passkey_recovery_required: { label: '需要通行密钥恢复', severity: 'warning' },
  auth_factor_key_unavailable: { label: '认证密钥不可用', severity: 'warning' },
  oauth_provider_create: { label: '创建身份提供商', severity: 'critical' },
  oauth_provider_update: { label: '更新身份提供商', severity: 'critical' },
  oauth_provider_active: { label: '启用身份提供商', severity: 'critical' },
  oauth_provider_disabled: { label: '停用身份提供商', severity: 'warning' },
  external_identity_link: { label: '绑定外部身份', severity: 'notice' },
  external_identity_unlink: { label: '解绑外部身份', severity: 'critical' },
  passkey_setting_update: { label: '更新通行密钥设置', severity: 'critical' },
  session_revoke: { label: '撤销会话', severity: 'warning' },
  oauth_consent: { label: '授权应用', severity: 'notice' },
  authorization_code_issue: { label: '签发授权码', severity: 'notice' },
  token_exchange: { label: '兑换令牌', severity: 'notice' },
  token_refresh: { label: '刷新令牌', severity: 'notice' },
  client_create: { label: '创建 OAuth 客户端', severity: 'notice' },
  consent_revoke: { label: '撤销授权', severity: 'warning' },
  oauth_consent_revoke: { label: '撤销授权', severity: 'warning' },
  authorization_request_rebound: { label: '授权请求换绑', severity: 'warning' },
  token_exchange_failure: { label: '兑换令牌失败', severity: 'warning' },
  token_refresh_failure: { label: '刷新令牌失败', severity: 'warning' },
  token_revoke: { label: '撤销令牌', severity: 'warning' },
  client_disabled: { label: '禁用 OAuth 客户端', severity: 'warning' },
  client_secret_rotate_conflict: { label: '轮换 Client Secret 冲突', severity: 'warning' },
  authorization_denied: { label: '拒绝授权', severity: 'info' },
  client_update: { label: '更新 OAuth 客户端', severity: 'critical' },
  client_active: { label: '启用 OAuth 客户端', severity: 'critical' },
  client_secret_rotate: { label: '轮换 Client Secret', severity: 'critical' },
  signing_key_rotate: { label: '轮换签名密钥', severity: 'critical' },
  signing_key_revoke: { label: '吊销签名密钥', severity: 'critical' },
  issuer_configure: { label: '配置 Issuer', severity: 'critical' },
  issuer_update: { label: '更新 Issuer', severity: 'critical' },
  user_avatar_update: { label: '更新头像', severity: 'info' },
  user_avatar_remove: { label: '移除头像', severity: 'info' },
  user_profile_update: { label: '更新资料', severity: 'info' },
  user_username_change: { label: '修改用户名', severity: 'critical' },
  user_email_change: { label: '修改邮箱', severity: 'critical' },
  user_register: { label: '用户注册', severity: 'notice' },
  registration_email_update: { label: '更新注册发件人', severity: 'notice' },
  plan_create: { label: '创建套餐', severity: 'notice' },
  plan_update: { label: '更新套餐', severity: 'notice' },
  plan_archive: { label: '归档套餐', severity: 'notice' },
  plan_restore: { label: '恢复套餐', severity: 'notice' },
  user_plan_assign: { label: '分配套餐', severity: 'notice' },
  admin_authorization_denied: { label: '管理授权被拒', severity: 'warning' },
  admin_owner_guard_denied: { label: 'Owner 保护拦截', severity: 'warning' },
  password_change: { label: '修改密码', severity: 'critical' },
  user_totp_factor_reset: { label: '重置 TOTP', severity: 'critical' },
  user_passkey_factor_reset: { label: '重置通行密钥', severity: 'critical' },
  user_totp_factor_enroll: { label: '登记 TOTP', severity: 'notice' },
  user_passkey_factor_enroll: { label: '登记通行密钥', severity: 'notice' },
  user_totp_factor_remove: { label: '移除 TOTP', severity: 'critical' },
  user_passkey_factor_remove: { label: '移除通行密钥', severity: 'critical' },
  owner_bootstrap: { label: '初始化 Owner', severity: 'critical' },
  user_create: { label: '创建用户', severity: 'critical' },
  user_active: { label: '启用用户', severity: 'critical' },
  user_disabled: { label: '禁用用户', severity: 'critical' },
  user_role_update: { label: '修改用户角色', severity: 'critical' },
  email_policy_update: { label: '更新邮箱策略', severity: 'critical' },
  registration_setting_update: { label: '更新注册设置', severity: 'critical' },
  invitation_code_create: { label: '生成邀请码', severity: 'critical' },
  invitation_code_disable: { label: '停用邀请码', severity: 'critical' },
  smtp_setting_update: { label: '更新 SMTP 设置', severity: 'critical' },
  security_limits_update: { label: '更新安全限流', severity: 'critical' },
  session_lifetime_update: { label: '更新会话有效期', severity: 'critical' },
}

export const RESOURCE_LABELS: Record<string, string> = {
  session: '会话',
  user: '用户',
  oauth_client: 'OAuth 客户端',
  oauth_provider: '身份提供商',
  oauth_authorization: 'OAuth 授权',
  oauth_token: 'OAuth 令牌',
  registration_invitation_code: '邀请码',
  plan: '套餐',
  setting: '系统设置',
  signing_key: '签名密钥',
  authentication_factor: '认证因素',
}

const ACTOR_LABELS: Record<string, string> = {
  admin: '管理员',
  user: '用户',
  system_token: '系统',
  system: '系统',
  bootstrap: '系统初始化',
  oauth_client: 'OAuth 客户端',
}

const SEVERITY_LABEL: Record<AuditSeverity, string> = {
  info: '信息',
  notice: '通知',
  warning: '警告',
  critical: '严重',
}

export function lookupAction(action: string | undefined): ActionInfo | undefined {
  if (!action) return undefined
  return Object.prototype.hasOwnProperty.call(ACTION_CATALOG, action) ? ACTION_CATALOG[action] : undefined
}

export function actionSeverity(action: string | undefined): AuditSeverity {
  return lookupAction(action)?.severity ?? 'info'
}

export function severityTone(severity: AuditSeverity): 'neutral' | 'success' | 'warning' {
  if (severity === 'notice') return 'success'
  if (severity === 'warning' || severity === 'critical') return 'warning'
  return 'neutral'
}

export function formatActor(type?: string, id?: string | null): string {
  const name = (type && ACTOR_LABELS[type]) || type || '—'
  return id ? `${name} #${id}` : name
}

export function resourceLabel(type?: string): string {
  if (!type) return '—'
  return RESOURCE_LABELS[type] || type
}

export function ActionBadge({ action }: { action: string }) {
  const known = lookupAction(action)
  if (!known) return <span className="chenxing-mono text-sm">{action || '—'}</span>
  return <Badge tone={severityTone(known.severity)}>{known.label}</Badge>
}

export function SeverityBadge({ action }: { action: string }) {
  const severity = actionSeverity(action)
  return <Badge tone={severityTone(severity)}>{SEVERITY_LABEL[severity]}</Badge>
}

function catalogOptions(labels: Record<string, string>, empty: string): SelectOption[] {
  return [
    { value: '', label: empty },
    ...Object.entries(labels).map(([value, label]) => ({ value, label: `${label}（${value}）` })),
  ]
}

export const ACTION_FILTER_OPTIONS: SelectOption[] = catalogOptions(
  Object.fromEntries(Object.entries(ACTION_CATALOG).map(([value, info]) => [value, info.label])),
  '全部事件',
)

export const RESOURCE_FILTER_OPTIONS: SelectOption[] = catalogOptions(RESOURCE_LABELS, '全部资源')

/** 当前筛选值不在目录里时追加一项，避免 Select 把历史未知值吞掉。 */
export function withCurrentOption(options: SelectOption[], current: string): SelectOption[] {
  if (!current || options.some((option) => option.value === current)) return options
  return [...options, { value: current, label: current }]
}
