import { BrandMark, HudPanel, Icon } from '@chenxing/ui'
import { OAuthShell } from '../components/shells'

export type OAuthHandoffDecision = 'approve' | 'deny'

/**
 * 确认页决策成功、整页跳回接入应用之前的交接视图。
 *
 * 跳转前必须抹掉地址里的 request_id（#196），而确认页按 request_id 挂载；如果
 * 这时继续渲染确认页，它会以「缺少 request_id」报错——可服务端早已处理完决策、
 * 授权码也已签发。回调页加载慢（本地回环端口、应用先换 token 再响应）时，
 * 用户就只能看到这条假错误。所以交接态不依赖 URL，只陈述已经发生的事实。
 */
export function OAuthHandoffView({ decision }: { decision: OAuthHandoffDecision }) {
  const approved = decision === 'approve'
  return (
    <OAuthShell>
      <HudPanel className="oauth-card" role="region" aria-live="polite" aria-label="辰星通行证授权结果">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">{approved ? '授权完成 · 正在返回接入应用' : '已取消授权 · 正在返回接入应用'}</span>
        </div>
        <div className="oauth-center">
          <div className="oauth-transfer" aria-hidden="true">
            <span className="oauth-transfer-mark">
              <BrandMark className="h-9 w-9 rounded-[10px] object-contain" />
            </span>
            <span className="oauth-beam" />
            <span className="oauth-transfer-mark is-client">A</span>
          </div>
          <div className="flex items-center justify-center gap-2 text-sm font-medium text-[var(--chenxing-foreground)]">
            <Icon name="refresh-cw" className="oauth-spin text-[var(--chenxing-cyan)]" size={15} />
            正在返回接入应用
          </div>
          <p className="oauth-copy is-hint">
            {approved ? '授权已完成。' : '已告知接入应用你取消了授权。'}
            如果页面长时间没有跳转，请直接回到应用查看结果。
          </p>
        </div>
      </HudPanel>
    </OAuthShell>
  )
}
