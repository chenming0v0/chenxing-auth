import { Component, type ReactNode } from 'react'
import { AuthPanel } from './shells'
import { SpaceBackdrop } from './space'
import { BrandLockup, Button } from './ui'

type ErrorBoundaryProps = { children: ReactNode }

type ErrorBoundaryState = { hasError: boolean }

/**
 * 根级错误边界（#227）：包住整个 App，任何渲染期崩溃都落到统一的恢复界面。
 *
 * 安全约定：
 * - 恢复界面只展示通用文案，绝不渲染错误消息、堆栈或内部状态——错误内容可能
 *   携带令牌、URL 查询等敏感信息。
 * - 刻意不实现 componentDidCatch：任何日志都会冒泄漏风险。React 19 默认会在
 *   onCaughtError 里把完整错误打到控制台，main.tsx 已在 createRoot 层显式替换
 *   为不含错误细节的固定标记，这里不需要也不应该再打印任何东西。
 * - 恢复路径不依赖 router / AuthProvider：刷新是原生 location.reload()，
 *   返回首页是原生 <a href="/"> 整页导航，即使 SPA 路由或 App 树已崩溃也能用。
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      return (
        <SpaceBackdrop opacity={0.7} className="chenxing-auth-layout">
          <AuthPanel>
            <div className="flex flex-col items-start gap-3">
              <BrandLockup />
              <h1 className="chenxing-h1 mt-1">界面遇到问题</h1>
              <p className="chenxing-caption">
                页面未能正常加载。请刷新重试，或返回首页。
              </p>
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <Button onClick={() => window.location.reload()}>刷新页面</Button>
                <a href="/" className="chenxing-btn-ghost">返回首页</a>
              </div>
            </div>
          </AuthPanel>
        </SpaceBackdrop>
      )
    }
    return this.props.children
  }
}
