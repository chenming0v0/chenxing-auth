import { Link } from '../router'
import { ArrowRight, Check, ShieldCheck, Sparkles } from 'lucide-react'
import { AuthShell } from '../components/shells'
import { HudPanel, Icon } from '../components/ui'

export function LandingPage() {
  return (
    <AuthShell action="登录" actionTo="/login">
      <div className="hero-layout">
        <section className="hero-copy">
          <span className="eyebrow">CHENXING PASSPORT · 01</span>
          <h1><strong>天穹辰星</strong>一个通行证，<br />连接所有星门。</h1>
          <p className="hero-description">统一身份认证、清晰的授权边界和可追溯的安全状态。为你的应用接入一套安静、可靠的登录体验。</p>
          <div className="hero-actions">
            <Link className="chenxing-btn-primary" to="/register"><Icon name="rocket" size={17} />创建通行证 <ArrowRight size={16} /></Link>
            <Link className="chenxing-btn-ghost" to="/console"><Icon name="layout-dashboard" size={16} />浏览控制台</Link>
          </div>
          <div className="hero-telemetry">
            <div className="telemetry-item"><strong>99.99%</strong><span>认证服务可用性</span></div>
            <div className="telemetry-item"><strong>OAUTH 2.0</strong><span>开放协议标准</span></div>
            <div className="telemetry-item"><strong>JWK / JWKS</strong><span>可轮换签名密钥</span></div>
          </div>
        </section>
        <HudPanel className="hero-panel">
          <div><span className="chenxing-chip"><Sparkles size={13} />身份中枢 · 在线</span><div className="panel-orbit"><div className="orbit-core"><ShieldCheck size={38} /></div></div></div>
          <div className="telemetry-list">
            <div className="telemetry-row"><span>会话状态</span><strong><Check size={13} /> ACTIVE</strong></div>
            <div className="telemetry-row"><span>密钥轮换</span><strong><Check size={13} /> READY</strong></div>
            <div className="telemetry-row"><span>边界策略</span><strong><Check size={13} /> ENFORCED</strong></div>
          </div>
        </HudPanel>
      </div>
    </AuthShell>
  )
}
