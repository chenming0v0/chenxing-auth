import { useCallback, useEffect, useRef, useState, type CSSProperties, type RefObject } from 'react'
import { Link } from '../router'
import { AuthShell } from '../components/shells'
import { BrandMark, HudPanel, Icon } from '../components/ui'
import { CountUp, DrawLine, Reveal, Typewriter, usePrefersReducedMotion } from '../components/motion'
import { WarpField } from '../components/space'
import { IntroGate } from '../components/intro-gate'

const stats = [
  { target: 12.8, decimals: 1, suffix: 'M', label: '已签发通行证' },
  { target: 3402, grouping: true, suffix: '', label: '接入应用' },
  { target: 99.997, decimals: 3, suffix: '%', label: '认证可用性' },
  { target: 38, suffix: 'ms', label: '平均签发耗时' },
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

const marqueeItems = [
  'OAuth 2.0', 'OpenID Connect', 'PKCE S256', 'JWKS', 'Discovery', 'Authorization Code',
  'Refresh Token', 'Key Rotation', 'CSRF Bound', 'Session TTL', 'Audit Trail', 'Rate Limit',
]

const typedWords = ['统一身份基座', 'OAuth 2.0 授权码流', 'OIDC Discovery 就绪', 'PKCE 单次授权码', '可轮换签名密钥']

export const LANDING_AUTHORIZATION_CTA_PATH = '/console/playground'
export const LANDING_TOKEN_ENDPOINT = 'https://auth.clya.top/oauth/token'

/* hero 左栏特性清单：一行一个能力点，配圆形图标（参考站的列表式排版） */
const heroPoints = [
  { icon: 'shield-check', text: 'OAuth 2.0 授权码流，PKCE 全程保护' },
  { icon: 'globe', text: 'OIDC Discovery 与 JWKS，端点开箱可用' },
  { icon: 'key-round', text: '签名密钥可轮换，按 kid 选择验签' },
  { icon: 'terminal', text: '内置 OAuth 连接测试台，接入即可调试' },
]

/* 顶栏微标签随滚动分区切换（lamalama data-labels 同款行为）：
   每个分区顶边越过视口 45% 线后接管标签，页面触底时固定为品牌名。
   标签文字变化会让 ScrambleText 重新走一遍乱码解码，即「回退再显示」。
   用 scroll + rAF 而不是 IntersectionObserver：需要的是「最后一个越线分区」
   这种有序判定和触底这个全局条件，单个滚动回调里一次算清比四个观察器
   互相仲裁简单得多。 */
function useScrollStatusLabel(
  marks: readonly (readonly [RefObject<HTMLElement | null>, string])[],
  base: string,
  bottom: string,
) {
  const [label, setLabel] = useState(base)
  const marksRef = useRef(marks)
  marksRef.current = marks
  useEffect(() => {
    let raf = 0
    const update = () => {
      raf = 0
      /* -48px 容差：滚动条物理触底前一点点就算到底，避免差 1px 永远不触发 */
      if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 48) {
        setLabel(bottom)
        return
      }
      let next = base
      for (const [ref, sectionLabel] of marksRef.current) {
        const el = ref.current
        if (el && el.getBoundingClientRect().top < window.innerHeight * 0.45) next = sectionLabel
      }
      setLabel(next)
    }
    const onScroll = () => {
      if (!raf) raf = requestAnimationFrame(update)
    }
    update()
    window.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', onScroll, { passive: true })
    return () => {
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', onScroll)
      if (raf) cancelAnimationFrame(raf)
    }
  }, [base, bottom])
  return label
}

/* 开场闸门只在本会话第一次进主页时播放，之后经 sessionStorage 跳过 */
const INTRO_SEEN_KEY = 'cx-intro-seen'
function introSeen() {
  try {
    return sessionStorage.getItem(INTRO_SEEN_KEY) === '1'
  } catch {
    return true
  }
}

export function LandingPage() {
  const reduced = usePrefersReducedMotion()
  const [introDone, setIntroDone] = useState(introSeen)
  const showIntro = !introDone && !reduced
  /* 开场播放期间 hero 编排整体后移，盖板滑出后第一幕刚好开始 */
  const base = showIntro ? 1350 : 0
  const d = (ms: number) => ({ '--hero-delay': `${base + ms}ms` }) as CSSProperties

  /* 顶栏微标签的分区锚点：授权流程 → 授权信任，能力矩阵 → 基础建设，
     CTA → 身份象征；触底显示品牌名，未越线时回落到「认证中枢」 */
  const flowRef = useRef<HTMLElement>(null)
  const infraRef = useRef<HTMLElement>(null)
  const ctaRef = useRef<HTMLElement>(null)
  const statusLabel = useScrollStatusLabel(
    [[flowRef, '授权信任'], [infraRef, '基础建设'], [ctaRef, '身份象征']],
    '认证中枢',
    '天穹辰星',
  )

  const handleIntroDone = useCallback(() => {
    try {
      sessionStorage.setItem(INTRO_SEEN_KEY, '1')
    } catch { /* 隐私模式下不可写也无妨，下次重播 */ }
    setIntroDone(true)
  }, [])

  return (
    <AuthShell
      status={statusLabel}
      action="登录"
      actionTo="/login"
      className=""
      menuExtra={(
        <div className="flex gap-2">
          <Link to="/register" className="chenxing-btn-primary flex-1 text-sm">创建通行证</Link>
          <Link to="/login" className="chenxing-btn-ghost flex-1 text-sm">登录</Link>
        </div>
      )}
    >
      {showIntro ? <IntroGate onDone={handleIntroDone} /> : null}
      <div className="relative z-[var(--chenxing-z-content)]" inert={showIntro ? true : undefined} aria-hidden={showIntro || undefined}>
        {/* 参考站式两栏 hero：左侧文案 + 特性清单 + CTA，右侧终端示例卡。
            替代旧版贴底竖排巨字 + 大号轨道 logo 的破格布局。 */}
        <section className="relative flex min-h-screen flex-col justify-center overflow-hidden px-6 pb-24 pt-32 sm:px-10">
          <WarpField className="cx-warp-mask absolute inset-0 h-full w-full opacity-90" />

          {/* HUD 取景框：四角括号 + 上下沿遥测读数，纯装饰 */}
          <div aria-hidden="true" className="pointer-events-none absolute inset-x-5 bottom-14 top-6 hidden sm:block">
            <span className="absolute left-0 top-0 h-5 w-5 border-l border-t border-[rgba(103,232,249,0.45)]" />
            <span className="absolute right-0 top-0 h-5 w-5 border-r border-t border-[rgba(103,232,249,0.45)]" />
            <span className="absolute bottom-0 left-0 h-5 w-5 border-b border-l border-[rgba(103,232,249,0.45)]" />
            <span className="absolute bottom-0 right-0 h-5 w-5 border-b border-r border-[rgba(103,232,249,0.45)]" />
            <span className="chenxing-mono absolute left-8 top-0.5 text-[9px] uppercase tracking-[0.32em] text-[rgba(103,232,249,0.55)]">CX-AUTH // Identity Core</span>
            <span className="chenxing-mono absolute right-8 top-0.5 text-[9px] uppercase tracking-[0.32em] text-[rgba(103,232,249,0.55)]">RA 05h 35m · Dec −05° 23′</span>
            <span className="chenxing-mono absolute bottom-0.5 left-8 text-[9px] uppercase tracking-[0.32em] text-[rgba(147,167,199,0.5)]">Star-Gate Online</span>
            <span className="chenxing-mono absolute bottom-0.5 right-8 text-[9px] uppercase tracking-[0.32em] text-[rgba(147,167,199,0.5)]">Sign 38ms</span>
          </div>

          {/* 竖排舷侧读数 */}
          <span aria-hidden="true" className="chenxing-mono absolute left-9 top-1/2 hidden -translate-y-1/2 text-[10px] uppercase tracking-[0.6em] text-[rgba(147,167,199,0.4)] [writing-mode:vertical-rl] lg:block">Tianqiong Chenxing</span>
          <span aria-hidden="true" className="chenxing-mono absolute right-9 top-1/2 hidden -translate-y-1/2 text-[10px] uppercase tracking-[0.6em] text-[rgba(147,167,199,0.4)] [writing-mode:vertical-rl] lg:block">OAuth 2.0 · OpenID Connect</span>

          <div className="relative mx-auto grid w-full max-w-6xl items-center gap-14 text-left lg:grid-cols-[minmax(0,11fr)_minmax(0,10fr)] lg:gap-16">
            {/* 左栏：眉题 → 横排标题 → 打字机 → 描述 → 特性清单 → CTA */}
            <div>
              <h1 className="chenxing-display font-bold leading-[1.14] tracking-[0.03em]">
                <span className="cx-mask block"><span className="cx-mask-inner chenxing-text-shimmer block text-[13vw] sm:text-[58px] lg:text-[64px]" style={d(300)}>天穹辰星</span></span>
                <span className="cx-mask mt-1 block"><span className="cx-mask-inner block text-[6.5vw] text-[var(--chenxing-foreground)] sm:text-[30px] lg:text-[34px]" style={d(420)}>一套通行证，接入所有应用</span></span>
              </h1>
              <p className="cx-mask mt-5"><span className="cx-mask-inner chenxing-mono text-xs uppercase tracking-[0.28em] text-[var(--chenxing-cyan)] sm:text-[13px]" style={d(540)}>
                <Typewriter words={typedWords} />
              </span></p>
              <p className="cx-mask mt-6 max-w-xl"><span className="cx-mask-inner chenxing-body leading-[1.9] text-[var(--chenxing-muted-foreground)]" style={d(640)}>
                一套贯通所有星域的统一身份基座。以 <span className="text-[var(--chenxing-foreground)]">辰星通行证</span> 为核心，为你的每一个应用提供符合 OAuth 2.0 与 OIDC 规范的授权、令牌与风控能力。
              </span></p>
              <ul className="mt-8 space-y-1">
                {heroPoints.map((point, index) => (
                  <li key={point.text} className="cx-hero-in cx-point-row -mx-3 flex items-center gap-4 rounded-[var(--chenxing-radius-md)] px-3 py-2.5" style={d(740 + index * 90)}>
                    <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-[var(--chenxing-radius-md)] bg-[rgba(255,255,255,0.06)] text-white">
                      <Icon name={point.icon} size={17} />
                    </span>
                    <span className="chenxing-body text-[15px] font-semibold text-[var(--chenxing-foreground)]">{point.text}</span>
                  </li>
                ))}
              </ul>
              <div className="cx-hero-in mt-10 flex flex-wrap items-center gap-3" style={d(1120)}>
                <Link to="/register" className="chenxing-btn-primary text-base"><Icon name="sparkles" size={16} />创建辰星通行证</Link>
                <Link to={LANDING_AUTHORIZATION_CTA_PATH} className="chenxing-btn-ghost text-base"><Icon name="zap" size={16} />体验授权流程</Link>
                <Link to="/console/playground" className="chenxing-btn-ghost text-base"><Icon name="terminal" size={16} />OAuth 连接测试</Link>
              </div>
            </div>

            {/* 右栏：悬浮 logo + 终端示例卡。示例为装饰性内容，token 一律截断假值 */}
            <div className="cx-hero-in" style={d(520)}>
              <div aria-hidden="true" className="pointer-events-none mb-12 hidden justify-center lg:flex">
                <span className="cx-float block">
                  <BrandMark className="h-36 w-36 rounded-full drop-shadow-[0_0_40px_rgba(56,189,248,0.55)]" />
                </span>
              </div>
              <HudPanel className="overflow-hidden !p-0">
                <div className="relative flex items-center gap-2 border-b border-[var(--chenxing-border)] bg-[rgba(4,8,16,0.45)] px-4 py-3">
                  <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-[rgba(255,107,107,0.5)]" />
                  <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-[rgba(245,199,106,0.5)]" />
                  <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-[rgba(52,211,153,0.5)]" />
                  <span className="chenxing-mono absolute left-1/2 -translate-x-1/2 text-[10px] uppercase tracking-[0.24em] text-[var(--chenxing-muted-foreground)]">&gt;_ terminal</span>
                  <span aria-hidden="true" className="ml-auto text-[var(--chenxing-muted-foreground)]"><Icon name="copy" size={13} /></span>
                </div>
                <pre className="chenxing-mono overflow-x-auto px-5 py-5 text-[11.5px] leading-[1.9] text-[var(--chenxing-muted-foreground)] sm:text-[12.5px]">
                  <code>
                    <span>$ </span><span className="font-semibold text-[var(--chenxing-cyan)]">curl</span> <span className="text-[var(--chenxing-ice)]">{LANDING_TOKEN_ENDPOINT}</span> \{'\n'}
                    {'    '}<span className="text-[var(--chenxing-gold)]">-X</span> POST \{'\n'}
                    {'    '}<span className="text-[var(--chenxing-gold)]">-d</span> <span className="text-[var(--chenxing-ice)]">'grant_type=authorization_code'</span> \{'\n'}
                    {'    '}<span className="text-[var(--chenxing-gold)]">-d</span> <span className="text-[var(--chenxing-ice)]">'code=SplxlO...'</span> \{'\n'}
                    {'    '}<span className="text-[var(--chenxing-gold)]">-d</span> <span className="text-[var(--chenxing-ice)]">'code_verifier=dBjftJ...'</span>
                  </code>
                </pre>
                <div aria-hidden="true" className="mx-5 h-px bg-[var(--chenxing-border)]" />
                <pre className="chenxing-mono overflow-x-auto px-5 py-5 text-[11.5px] leading-[1.9] text-[var(--chenxing-muted-foreground)] sm:text-[12.5px]">
                  <code>
                    {'{'}{'\n'}
                    {'  '}<span className="text-[var(--chenxing-cyan)]">"access_token"</span>: <span className="text-[var(--chenxing-gold)]">"eyJhbG..."</span>,{'\n'}
                    {'  '}<span className="text-[var(--chenxing-cyan)]">"token_type"</span>: <span className="text-[var(--chenxing-gold)]">"Bearer"</span>,{'\n'}
                    {'  '}<span className="text-[var(--chenxing-cyan)]">"expires_in"</span>: <span className="text-[var(--chenxing-ice)]">3600</span>,{'\n'}
                    {'  '}<span className="text-[var(--chenxing-cyan)]">"id_token"</span>: <span className="text-[var(--chenxing-gold)]">"eyJhbG..."</span>{'\n'}
                    {'}'}
                  </code>
                </pre>
              </HudPanel>
            </div>
          </div>
        </section>

        {/* 协议术语跑马灯：纯装饰，aria-hidden 不进无障碍树 */}
        <section aria-hidden="true" className="cx-marquee relative border-y border-[var(--chenxing-border)] py-4">
          <div className="cx-marquee-track">
            {[0, 1].map((copy) => (
              <div key={copy} className="flex shrink-0 items-center">
                {marqueeItems.map((item) => (
                  <span key={item} className="chenxing-mono flex items-center text-[11px] uppercase tracking-[0.32em] text-[var(--chenxing-muted-foreground)]">
                    <span className="px-7">{item}</span>
                    <span className="text-[10px] text-[var(--chenxing-gold)]">✦</span>
                  </span>
                ))}
              </div>
            ))}
          </div>
        </section>

        <section id="landing-stats" className="mx-auto max-w-4xl scroll-mt-24 px-6 py-24">
          <Reveal>
            <div className="grid grid-cols-2 gap-px overflow-hidden rounded-[var(--chenxing-radius-lg)] border border-[rgba(255,255,255,0.10)] bg-[rgba(255,255,255,0.06)] sm:grid-cols-4">
              {stats.map((item) => (
                <div key={item.label} className="cx-stat-cell bg-[rgba(6,10,20,0.82)] px-4 py-6 backdrop-blur-xl">
                  <div className="cx-stat-value chenxing-mono text-2xl font-bold text-[var(--chenxing-foreground)] sm:text-[28px]">
                    <CountUp target={item.target} decimals={item.decimals ?? 0} suffix={item.suffix} grouping={item.grouping ?? false} />
                  </div>
                  <div className="chenxing-caption mt-1 text-[11px] tracking-wider">{item.label}</div>
                </div>
              ))}
            </div>
          </Reveal>
        </section>

        <section ref={flowRef} id="landing-flow" className="mx-auto max-w-6xl scroll-mt-24 px-6 py-20">
          <Reveal variant="mask">
            <div className="relative">
              <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">[ Authorization Flow ]</p>
              <h2 className="chenxing-display mt-3 max-w-xl text-3xl font-bold leading-tight text-[var(--chenxing-foreground)] sm:text-[38px]">
                四步完成一次<span className="chenxing-text-shimmer">可信授权</span>
              </h2>
            </div>
          </Reveal>
          <div className="relative mt-12">
            <span aria-hidden="true" className="cx-steps-line hidden xl:block" />
            <div className="relative grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              {steps.map((step, index) => (
                <Reveal key={step.n} delay={index * 110}>
                  <HudPanel className="cx-lift group h-full overflow-hidden">
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
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section ref={infraRef} id="landing-features" className="mx-auto max-w-6xl scroll-mt-24 px-6 py-16">
          <Reveal variant="mask">
            <div className="relative">
              <p className="chenxing-mono text-[10px] uppercase tracking-[0.3em] text-[var(--chenxing-cyan)]">[ Platform Capabilities ]</p>
              <h2 className="chenxing-display mt-3 max-w-2xl text-3xl font-bold leading-tight sm:text-[36px]">为接入方准备的身份基础设施</h2>
            </div>
          </Reveal>
          <div className="mt-10 grid gap-4 md:grid-cols-2">
            {features.map((feature, index) => (
              <Reveal key={feature.title} delay={index * 90}>
                <HudPanel className="cx-lift h-full !p-6">
                  <div className="cx-feature-icon mb-4 inline-flex h-10 w-10 items-center justify-center rounded-[var(--chenxing-radius-md)] bg-[rgba(255,255,255,0.08)] text-white">
                    <Icon name={feature.icon} size={18} />
                  </div>
                  <h3 className="chenxing-h3">{feature.title}</h3>
                  <p className="chenxing-caption mt-2 leading-relaxed">{feature.copy}</p>
                </HudPanel>
              </Reveal>
            ))}
          </div>
        </section>

        <section ref={ctaRef} className="mx-auto max-w-6xl px-6 py-24">
          <Reveal>
            <HudPanel className="overflow-hidden text-center">
              <div aria-hidden="true" className="cx-aurora absolute -inset-8" />
              <div aria-hidden="true" className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-[rgba(255,217,138,0.6)] to-transparent" />
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
          </Reveal>
        </section>

        <footer className="bg-[rgba(4,6,13,0.6)] pb-12">
          <div className="mx-auto max-w-6xl px-6">
            <DrawLine />
          </div>
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
