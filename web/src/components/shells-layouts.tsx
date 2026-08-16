import type { ReactNode } from 'react'
import { HudPanel, BrandMark, Notice } from './ui'
import { SpaceBackdrop } from './space'
import { SkipLink, SkipTarget, useSkipTargetId } from './skip-link'
import { GlobalTopbar } from './shells-topbar'

export function AuthShell({
  children,
  status,
  action,
  actionTo,
  className = 'chenxing-auth-layout',
  menuExtra,
  links,
}: {
  children: ReactNode
  status: ReactNode
  action?: string
  actionTo?: string
  className?: string
  menuExtra?: ReactNode
  links?: readonly { label: string; href: string }[]
}) {
  /* 跳过链接是 Shell 的第一个可聚焦元素，内容锚点紧跟顶栏之后（见 skip-link.tsx） */
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop className={className} opacity={0.7}>
      <SkipLink targetId={targetId} />
      <GlobalTopbar status={status} action={action} actionTo={actionTo} menuExtra={menuExtra} links={links} />
      <SkipTarget targetId={targetId} />
      {children}
    </SpaceBackdrop>
  )
}

export function AuthPanel({ children, className = 'w-full max-w-md' }: { children: ReactNode; className?: string }) {
  return (
    <section className="relative z-[var(--chenxing-z-content)] flex flex-1 items-center justify-center px-6 py-14 lg:px-12">
      <div className={className}>
        <HudPanel>{children}</HudPanel>
        <p className="chenxing-mono mt-6 text-center text-[10px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]">
          Encrypted Gateway · 天穹辰星
        </p>
      </div>
    </section>
  )
}

export function OAuthShell({ children, footer = true }: { children: ReactNode; footer?: boolean }) {
  const targetId = useSkipTargetId()
  return (
    <SpaceBackdrop opacity={0.6}>
      <SkipLink targetId={targetId} />
      <section className="oauth-shell">
        <SkipTarget targetId={targetId} />
        {children}
        {footer ? (
          <div className="oauth-footer">
            {/* #240：语言选择与帮助/隐私权/条款均无对应行为，静态文本而非伪控件 */}
            <span className="oauth-footer-label">简体中文</span>
            <div className="oauth-footer-links">
              <span className="oauth-footer-label">帮助</span>
              <span className="oauth-footer-label">隐私权</span>
              <span className="oauth-footer-label">条款</span>
            </div>
          </div>
        ) : null}
      </section>
    </SpaceBackdrop>
  )
}

export function LoadingPanel({ message }: { message: string }) {
  return (
    <HudPanel className="w-full max-w-md">
      <Notice tone="info">{message}</Notice>
    </HudPanel>
  )
}

export function BrandMarkOnly() {
  return <BrandMark />
}
