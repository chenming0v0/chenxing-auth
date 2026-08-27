import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { ErrorBoundary } from '@chenxing/ui'
import './index.css'

// 错误消息与堆栈可能携带令牌、URL 查询等敏感信息，一律不进控制台。
// React 19 默认会在 onCaughtError / onUncaughtError 里打印完整错误，这里
// 显式替换为不含任何错误细节的固定标记；需要诊断时用 React DevTools 复现。
// ErrorBoundary 自身不写日志（见 error-boundary.tsx 的安全约定），两层都不泄漏。
function withholdErrorLog(label: string): () => void {
  return () => console.error(`[chenxing] ${label}; details withheld.`)
}

createRoot(document.getElementById('root')!, {
  onCaughtError: withholdErrorLog('UI recovered from a render error'),
  onUncaughtError: withholdErrorLog('UI hit an uncaught error'),
}).render(
  <StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </StrictMode>,
)
