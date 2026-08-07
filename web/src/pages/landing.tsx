import { Link } from '../router'
import { AuthShell } from '../components/shells'
import { BrandMark, HudPanel, Icon } from '../components/ui'

const stats = [
  { value: '12.8M', label: '已签发通行证' },
  { value: '3,402', label: '接入应用' },
  { value: '99.997%', label: '认证可用性' },
  { value: '38ms', label: '平均签发耗时' },
]

const steps = [
  { n: '01', title: '发起授权', copy: '第三方应用携带 client_id、scope 与 PKCE challenge 跳转至认证中枢' },
  { n: '02', title: '身份确认', copy: '用户通过辰星通行证完成登录、二次验证与会话绑定' },
  { n: '03', title: '授权确认', copy: '展示应用与权限范围，用户明确批准或拒绝访问请求' },
  { n: '04', title: '签发回跳', copy: '授权码短时有效、单次使用，并绑定 Redirect URI 与会话' },
]

const features = [
  { icon: 'shield-check', title: 'OAuth 2.0 / OIDC', copy: '标准授权码流、PKCE、Discovery 与 JWKS，开箱即可接入。' },
  { icon: 'key-round', title: '密钥可轮换', copy: '签名密钥按 kid 选择公钥，轮换时保留旧公钥验证窗口。' },
  { icon: 'lock', title: '会话边界清晰', copy: 'Cookie、CSRF 与短期授权状态分层管理，敏感值不进日志。' },
  { icon: 'gauge', title: '可运营后台', copy: '用户、Client、审计与系统设置统一收口，权限可追踪。' },
]

export function LandingPage() {
  return (
    <AuthShell
      status="星门在线"
      action="登录"
      actionTo="/login"
      className=""
      menuExtra={(
        <>
          <div className="chenxing-divider my-1" />
          <Link to="/register" className="chenxing-btn-primary w-full text-sm">创建通行证</Link>
        </>
      )}
    >
      <div className="relative z-[var(--chenxing-z-content)]">
        <section className="relative mx-auto flex min-h-[88vh] max-w-6xl flex-col items-center justify-center px-6 pb-16 pt-20 text-center">
          <div className="relative mb-10 flex h-36 w-36 items-center justify-center">
            <span className="absolute -inset-10 rounded-full border border-[var(--chenxing-border)] opacity-60" />
            <span className="absolute -inset-5 animate-[spin_22s_linear_infinite] motion-reduce:animate-none rounded-full border border-dashed border-[rgba(245,199,106,0.3)]">
              <span className="absolute -top-1 left-1/2 h-2 w-2 -translate-x-1/2 rounded-full bg-[var(--chenxing-gold)] shadow-[0_0_14px_4px_rgba(245,199,106,0.7)]" />
            </span>
            <span className="absolute inset-1 animate-[spin_16s_linear_infinite_reverse] motion-reduce:animate-none rounded-full border border-[rgba(103,232,249,0.18)]">
              <span className="absolute -bottom-1 left-1/2 h-1.5 w-1.5 -translate-x-1/2 rounded-full bg-[var(--chenxing-cyan)] shadow-[0_0_12px_3px_rgba(103,232,249,0.7)]" />
            </span>
            <span className="absolute inset-0 rounded-full bg-[var(--chenxing-primary-soft)] blur-2xl" />
            <BrandMark className="relative h-28 w-28 animate-pulse motion-reduce:animate-none rounded-full drop-shadow-[0_0_28px_rgba(56,189,248,0.55)]" />
          </div>
          <span className="chenxing-chip"><span className="h-1.5 w-1.5 rounded-full bg-[var(--chenxing-cyan)]" />全星域认证服务运行中</span>
          <h1 className="chenxing-display mt-9 text-[17vw] font-bold leading-[0.92] tracking-[0.06em] sm:text-[92px]">
            <span className="chenxing-text-shimmer">天穹辰星</span>
          </h1>
          <div className="mt-5 flex items-center justify-center gap-4">
            <span className="h-px w-12 bg-gradient-to-r from-transparent to-[rgba(245,199,106,0.6)] sm:w-20" />
            <span className="chenxing-body text-sm font-semibold tracking-[0.5em] text-[var(--chenxing-gold)] sm:text-[17px]">辰星认证中枢</span>
            <span className="h-px w-12 bg-gradient-to-l from-transparent to-[rgba(245,199,106,0.6)] sm:w-20" />
          </div>
          <p className="chenxing-body mx-auto mt-9 max-w-[600px] leading-[1.9] text-[var(--chenxing-muted-foreground)]">
            一套贯通所有星域的统一身份基座。以 <span className="text-[var(--chenxing-foreground)]">辰星通行证</span> 为核心，为你的每一个应用提供符合 OAuth 2.0 与 OIDC 规范的授权、令牌与风控能力。
          </p>
          <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
            <Link to="/register" className="chenxing-btn-primary text-base"><Icon name="sparkles" size={16} />创建辰星通行证</Link>
            <Link to="/oauth/consent" className="chenxing-btn-ghost text-base"><Icon name="zap" size={16} />体验授权流程</Link>
            <Link to="/console/playground" className="chenxing-btn-ghost text-base"><Icon name="terminal" size={16} />OAuth 连接测试</Link>
          </div>
        </section>

        <section className="mx-auto max-w-4xl px-6 pb-24">
          <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[var(--chenxing-radius-lg)] border border-[rgba(255,255,255,0.10)] bg-[rgba(255,255,255,0.06)] sm:grid-cols-4">
            {stats.map((item) => (
              <div key={item.label} className="bg-[rgba(6,10,20,0.82)] px-4 py-6 backdrop-blur-xl">
                <div className="chenxing-mono text-2xl font-bold text-[var(--chenxing-foreground)] sm:text-[28px]">{item.value}</div>
                <div className="chenxing-caption mt-1 text-[11px] tracking-wider">{item.label}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-6 py-20">
          <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">// Authorization Flow</p>
          <h2 className="chenxing-display mt-3 max-w-xl text-3xl font-bold leading-tight text-[var(--chenxing-foreground)] sm:text-[38px]">
            四步完成一次<span className="text-[var(--chenxing-gold)]">可信授权</span>
          </h2>
          <div className="mt-12 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            {steps.map((step) => (
              <HudPanel key={step.n} className="group overflow-hidden">
                <div className="chenxing-mono absolute right-4 top-2 text-[52px] font-bold text-[rgba(255,255,255,0.05)] transition-colors group-hover:text-[rgba(255,255,255,0.09)]">{step.n}</div>
                <div className="relative">
                  <div className="mb-5 h-8 w-8 rounded-[var(--chenxing-radius-sm)] bg-[linear-gradient(135deg,rgba(56,189,248,0.55),rgba(103,232,249,0.3))] p-px">
                    <div className="chenxing-mono flex h-full w-full items-center justify-center rounded-[7px] bg-[#0a101f] text-xs font-bold text-[var(--chenxing-cyan)]">{step.n.slice(1)}</div>
                  </div>
                  <h3 className="chenxing-h3 text-base">{step.title}</h3>
                  <p className="chenxing-caption mt-2.5 leading-relaxed">{step.copy}</p>
                </div>
                <div className="mt-6 h-px w-full bg-gradient-to-r from-[rgba(56,189,248,0.5)] via-[rgba(103,232,249,0.3)] to-transparent" />
              </HudPanel>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-6 py-16">
          <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">// Platform Capabilities</p>
          <h2 className="chenxing-display mt-3 max-w-2xl text-3xl font-bold leading-tight sm:text-[36px]">为接入方准备的身份基础设施</h2>
          <div className="mt-10 grid gap-4 md:grid-cols-2">
            {features.map((feature) => (
              <HudPanel key={feature.title} className="!p-6">
                <div className="mb-4 inline-flex h-10 w-10 items-center justify-center rounded-[var(--chenxing-radius-md)] bg-[var(--chenxing-primary-soft)] text-[var(--chenxing-cyan)]">
                  <Icon name={feature.icon} size={18} />
                </div>
                <h3 className="chenxing-h3">{feature.title}</h3>
                <p className="chenxing-caption mt-2 leading-relaxed">{feature.copy}</p>
              </HudPanel>
            ))}
          </div>
        </section>

        <section className="mx-auto max-w-6xl px-6 py-24">
          <HudPanel className="overflow-hidden text-center">
            <div className="absolute inset-0 bg-[radial-gradient(70%_120%_at_50%_0%,rgba(56,189,248,0.2),transparent_70%)]" />
            <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(255,217,138,0.6)] to-transparent" />
            <div className="relative flex flex-col items-center py-8 sm:py-12">
              <BrandMark className="h-16 w-16 rounded-full drop-shadow-[0_0_20px_rgba(245,199,106,0.5)]" />
              <h2 className="chenxing-display mt-8 text-[28px] font-bold leading-tight text-[var(--chenxing-foreground)] sm:text-[40px]">
                让身份，成为你产品的<span className="chenxing-text-shimmer">第一印象</span>
              </h2>
              <p className="chenxing-caption mx-auto mt-4 max-w-xl leading-[1.9]">注册开发者账号，创建你的第一个 OAuth 客户端，把辰星通行证接入到你的项目里。</p>
              <div className="mt-9 flex flex-wrap justify-center gap-3">
                <Link to="/register" className="chenxing-btn-primary"><Icon name="lock" size={16} />立即创建通行证</Link>
                <Link to="/login" className="chenxing-btn-ghost">已有通行证 · 登录</Link>
              </div>
            </div>
          </HudPanel>
        </section>

        <footer className="border-t border-[var(--chenxing-border)] bg-[rgba(4,6,13,0.6)]">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-6 px-6 py-10">
            <div className="flex items-center gap-3">
              <BrandMark className="h-8 w-8 rounded-[var(--chenxing-radius-md)]" />
              <div className="leading-tight">
                <div className="chenxing-body text-xs font-semibold tracking-[0.2em]">天穹辰星 · 辰星认证中枢</div>
                <div className="chenxing-caption mt-1 text-[11px]">© 2026 TianQiong ChenXing. All rights reserved.</div>
              </div>
            </div>
            {/* #240：页脚栏目暂无对应页面，以静态文本呈现，不渲染 href="#" 的伪链接 */}
            <div className="chenxing-caption flex flex-wrap gap-6 text-[11.5px]">
              {['开发者文档', '服务条款', '隐私政策', '系统状态', '安全公告'].map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
          </div>
        </footer>
      </div>
    </AuthShell>
  )
}
