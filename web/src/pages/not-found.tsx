import { Link } from '../router'
import { AuthPanel, AuthShell } from '../components/shells'
import { Notice } from '@chenxing/ui'

/**
 * 未知路径的兜底页。此前未知路径会静默 Navigate 到 `/` 并播放首页开场动画，
 * 用户根本不知道自己请求的地址出了什么问题——移动端 OAuth 回调落到浏览器时
 * 授权码就是这样悄无声息丢掉的。现在明确告诉用户地址无效，并给出去处。
 */
export function NotFoundPage() {
  return (
    <AuthShell status="页面不存在">
      <AuthPanel>
        <div className="space-y-4">
          <Notice tone="warning">这个地址不存在，或者已经失效。</Notice>
          <Link to="/" className="chenxing-btn-primary w-full">回到首页</Link>
          <Link to="/console" className="chenxing-btn-ghost w-full">进入控制台</Link>
        </div>
      </AuthPanel>
    </AuthShell>
  )
}
