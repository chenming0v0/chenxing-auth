import { useLayoutEffect, useState } from 'react'
import { Link } from '../router'
import { OAuthShell } from '../components/shells'
import { BrandMark, HudPanel } from '@chenxing/ui'
import { scrubLocationQuery } from './oauth'

/**
 * 移动端客户端的回调地址形如 `https://<issuer>/app/<numeric_id>/oauth/callback`
 * （Android App Link）。系统没把链接交给应用时，浏览器会加载这个地址、后端返回
 * SPA 壳，此时必须由本页接住，而不是静默弹回首页丢掉授权码。
 * 只接受精确形态，不接受尾部斜杠等变体：后端注册的 redirect_uri 也是精确匹配。
 */
const APP_LINK_CALLBACK = /^\/app\/(\d+)\/oauth\/callback$/

export function matchAppLinkCallback(pathname: string): string | null {
  return APP_LINK_CALLBACK.exec(pathname)?.[1] ?? null
}

export function AppLinkCallbackPage() {
  // #196：与 OAuthRedirectPage 同理，先读后清。除结果分支外还固化完整的原始
  // href（含 code/state）：地址栏随后被 replaceState 抹掉，只有组件状态里
  // 还留着可以再次触发 App Link 的原始链接。把它留在内存而不是 URL 里，
  // 是因为 scrub 挡的是历史与 Referer 两条泄露路径；授权码本身一次性使用且
  // 通过 PKCE 绑定到发起授权的应用，同页锚点再次指向它是可接受的。
  const [callbackState] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    const hasError = Boolean(params.get('error')?.trim())
    const hasSuccess = Boolean(params.get('code')?.trim()) && Boolean(params.get('state')?.trim())
    return { href: window.location.href, hasError, hasSuccess, valid: hasError || hasSuccess }
  })

  // useLayoutEffect 先于绘制执行：避免敏感参数在地址栏闪现一个可被截图/观察的窗口
  useLayoutEffect(() => {
    scrubLocationQuery()
  }, [])

  // 必须是原生 <a> 而不是路由 Link：Android 只在用户点击触发的真实顶层导航上
  // 才会把已验证的 App Link 交给应用，SPA 内的 pushState 不会唤起应用。
  const openApp = (label: string) => (
    <a className="oauth-btn oauth-btn-primary" href={callbackState.href} rel="noreferrer">{label}</a>
  )

  return (
    <OAuthShell>
      {/* 页面主内容区：外层 OAuthShell 已提供唯一的 <main>，此处只能是 region。
          保留 aria-live 以便 SPA 内跳转到本页时播报授权结果 */}
      <HudPanel className="oauth-card" role="region" aria-live="polite" aria-label="辰星通行证授权结果">
        <div className="oauth-card-head">
          <BrandMark className="h-7 w-7 shrink-0 rounded-[var(--chenxing-radius-md)] object-contain" />
          <span className="chenxing-body text-sm">{!callbackState.valid ? '授权回调无效' : callbackState.hasError ? '授权未完成' : '授权完成 · 请返回应用'}</span>
        </div>
        <div className="oauth-center">
          <div className="oauth-transfer" aria-hidden="true">
            <span className="oauth-transfer-mark">
              <BrandMark className="h-9 w-9 rounded-[10px] object-contain" />
            </span>
            <span className="oauth-beam" />
            <span className="oauth-transfer-mark is-client">A</span>
          </div>
          {!callbackState.valid ? (
            <>
              <h1 className="oauth-title is-compact">授权回调无效</h1>
              <p className="oauth-copy is-notice">成功回调必须同时包含有效的 code 和 state；错误回调必须包含 error。请回到应用重新发起授权。</p>
              <div className="mt-6"><Link to="/console" className="oauth-btn oauth-btn-primary">返回控制台</Link></div>
            </>
          ) : callbackState.hasError ? (
            <>
              <h1 className="oauth-title is-compact">授权没有完成</h1>
              <p className="oauth-copy is-notice">授权请求被拒绝或未完成。请回到应用重试。</p>
              <div className="mt-6">{openApp('返回应用')}</div>
              <div className="mt-4"><Link to="/console" className="chenxing-link">返回控制台</Link></div>
            </>
          ) : (
            <>
              <h1 className="oauth-title is-compact">授权完成，请返回应用</h1>
              <p className="oauth-copy is-notice">浏览器没有把回调交给应用，可能是应用尚未安装，或系统还没有确认它对这个链接的归属。点击下方按钮再试一次，应用会自动继续登录。</p>
              <p className="oauth-copy is-hint">本页面不会展示授权码或 Token，授权码只对发起授权的应用有效。</p>
              <div className="mt-6">{openApp('打开应用继续')}</div>
              <div className="mt-4"><Link to="/console" className="chenxing-link">返回控制台</Link></div>
            </>
          )}
        </div>
      </HudPanel>
    </OAuthShell>
  )
}
