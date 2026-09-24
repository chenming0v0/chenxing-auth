import { useCallback, useMemo, useRef, useState } from 'react'
import { replaceUrl, useLocation } from '../../router'
import { ConsoleLayout } from '../../components/shells'
import { Icon, Notice, PageIntro, TopbarSubnav, type TopbarSubnavItem } from '@chenxing/ui'
import { AdminGate, useAdminAccess, type AdminAccess } from './shared'
import { EmailPolicyPanel } from './settings/email-policy-panel'
import { PasskeyPanel } from './settings/passkey-panel'
import { SecurityLimitsPanel } from './settings/security-limits-panel'
import { SessionLifetimePanel } from './settings/session-lifetime-panel'
import { SmtpPanel } from './settings/smtp-panel'
import { IssuerPanel } from './settings/issuer-panel'
import { RegistrationPanel } from './settings/registration-panel'
import { SigningKeyPanel } from './settings/signing-key-panel'
import { useDraftLeaveGuard, useFlashMessage } from './settings/panel'

export type SettingsTab = 'registration' | 'passkey' | 'email' | 'security' | 'session' | 'issuer'

const TABS: readonly (TopbarSubnavItem<SettingsTab> & { description: string })[] = [
  { value: 'registration', label: '注册', icon: 'user-plus', description: '公开注册与邮箱域名白名单' },
  { value: 'passkey', label: 'Passkey', icon: 'fingerprint', description: 'WebAuthn 无密码登录' },
  { value: 'email', label: '邮件', icon: 'send', description: 'SMTP 发信' },
  { value: 'security', label: '安全策略', icon: 'shield', description: '限流阈值与签名密钥' },
  { value: 'session', label: '会话', icon: 'clock-3', description: '登录保持时间' },
  { value: 'issuer', label: '发行者', icon: 'globe-2', description: 'OIDC Issuer' },
]

/** 发行者分栏只对有 manage_issuer 的管理员出现 */
export function settingsTabsFor(access: AdminAccess) {
  const canManageIssuer = Boolean(access.data?.permissions.includes('manage_issuer'))
  return TABS.filter((tab) => tab.value !== 'issuer' || canManageIssuer)
}

/** 分栏写在 ?tab= 里：刷新、分享、后退都停在同一分栏；非法值回落到第一个可见分栏。 */
function useSettingsTab(access: AdminAccess) {
  const location = useLocation()
  const tabs = settingsTabsFor(access)
  const requested = new URLSearchParams(location.search).get('tab')
  const tab = tabs.find((item) => item.value === requested)?.value ?? tabs[0].value
  /* 切分栏只是同页视图切换：用 replaceUrl，不进历史，也不触发未保存草稿的离开守卫 */
  const select = useCallback((next: SettingsTab) => replaceUrl(`/admin/settings?tab=${next}`), [])
  return { tabs, tab, select }
}

export function AdminSettings() {
  const access = useAdminAccess()
  const { tabs, tab, select } = useSettingsTab(access)
  const allowed = Boolean(access.data?.permissions.includes('manage_system_settings'))
  const current = tabs.find((item) => item.value === tab)
  return (
    <ConsoleLayout
      subnav={allowed ? (
        <TopbarSubnav label="系统设置分栏" items={tabs} value={tab} onChange={select} panelId={settingsPanelId} />
      ) : undefined}
    >
      {/* 设置是表单阅读场景：收窄到 4xl 居中，长表单不再横跨整块宽屏 */}
      <div className="mx-auto w-full max-w-4xl">
        <PageIntro
          eyebrow="// Admin · System"
          title={current && allowed ? `系统设置 · ${current.label}` : '系统设置'}
          description={current && allowed ? current.description : '配置辰星认证中枢的登录、邮件与安全策略。'}
        />
        <p className="chenxing-caption mb-6 flex items-center gap-1.5 text-[var(--chenxing-warning)]">
          <Icon name="lock" size={14} />
          敏感凭证为只写字段，保存后不会回显；日志与列表均不返回明文或哈希。
        </p>
        <AdminGate access={access} permission="manage_system_settings">
          <SettingsWorkspace access={access} tab={tab} />
        </AdminGate>
      </div>
    </ConsoleLayout>
  )
}

export function settingsPanelId(tab: SettingsTab) {
  return `settings-panel-${tab}`
}

export function SettingsWorkspace({ access, tab }: { access: AdminAccess; tab: SettingsTab }) {
  const canRotateKeys = Boolean(access.data?.permissions.includes('rotate_keys'))
  const tabs = settingsTabsFor(access)
  /* flash 的引用跨渲染稳定，面板的加载 effect 不会因为消息状态变化而重跑（#268）。 */
  const { flash, message } = useFlashMessage()

  /* #381：聚合各面板的未保存草稿。每个面板拿到独立且跨渲染稳定的上报回调
     （useMemo 锁定工厂产物），回调闭包各自记住自己的脏标记，只在状态翻转时更新
     计数——「一块面板保存后」不会把其它面板的脏标记清掉。 */
  const dirtyCount = useRef(0)
  const [dirty, setDirty] = useState(false)
  const makeDirtyReporter = useCallback(() => {
    let mine = false
    return (isDirty: boolean) => {
      if (isDirty === mine) return
      mine = isDirty
      dirtyCount.current += isDirty ? 1 : -1
      setDirty(dirtyCount.current > 0)
    }
  }, [])
  const reportPasskeyDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportEmailPolicyDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSmtpDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSecurityLimitsDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportSessionLifetimeDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportIssuerDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  const reportRegistrationDirty = useMemo(() => makeDirtyReporter(), [makeDirtyReporter])
  /* 任一面板有草稿时，路由跳转与刷新/关页前都提示确认。 */
  useDraftLeaveGuard(dirty)

  /* 所有分栏的面板始终挂载，只切换 hidden：卸载会让 useDirtyReport 把草稿标记清零，
     离开守卫就会误放行，切回来时草稿也已丢失。 */
  const panel = (value: SettingsTab, children: React.ReactNode) => {
    const item = tabs.find((entry) => entry.value === value)
    if (!item) return null
    return (
      /* 布局类放内层：Tailwind 的 display 工具类会压过 preflight 里零特异性的 [hidden] */
      <section id={settingsPanelId(value)} role="tabpanel" aria-label={item.label} hidden={tab !== value}>
        <div className="flex flex-col gap-6">{children}</div>
      </section>
    )
  }

  return (
    <div className="flex flex-col gap-6">
      {message ? <Notice tone={message.tone}>{message.text}</Notice> : null}
      {panel('registration', <>
        <RegistrationPanel onMessage={flash} onDirtyChange={reportRegistrationDirty} />
        <EmailPolicyPanel onMessage={flash} onDirtyChange={reportEmailPolicyDirty} />
      </>)}
      {panel('passkey', <PasskeyPanel onMessage={flash} onDirtyChange={reportPasskeyDirty} />)}
      {panel('email', <SmtpPanel onMessage={flash} onDirtyChange={reportSmtpDirty} />)}
      {panel('security', <>
        <SecurityLimitsPanel onMessage={flash} onDirtyChange={reportSecurityLimitsDirty} />
        <SigningKeyPanel canRotate={canRotateKeys} onMessage={flash} />
      </>)}
      {panel('session', <SessionLifetimePanel onMessage={flash} onDirtyChange={reportSessionLifetimeDirty} />)}
      {panel('issuer', <IssuerPanel onMessage={flash} onDirtyChange={reportIssuerDirty} />)}
    </div>
  )
}
