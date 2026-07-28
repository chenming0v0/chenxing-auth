import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ShieldCheck, Fingerprint, KeyRound, Orbit, ArrowRight,
  Zap, Globe2, Lock, Sparkles,
} from "lucide-react";
import Starfield from "../components/Starfield";
import { Logo, BrandMark, GlowButton, GhostButton } from "../components/ui";
import { BRAND } from "../data/mock";
import { useStore } from "../store";

const features = [
  { icon: <Fingerprint size={20} />, title: "一证通行", desc: "一个辰星通行证，畅行天穹辰星全系产品与第三方生态应用。" },
  { icon: <ShieldCheck size={20} />, title: "OAuth 2.1 / OIDC", desc: "标准授权码 + PKCE 流程，细粒度 Scope 控制，令牌自动轮换。" },
  { icon: <KeyRound size={20} />, title: "开发者友好", desc: "5 分钟接入。控制台一键创建应用，内置授权测试台实时调试。" },
  { icon: <Orbit size={20} />, title: "授权全掌控", desc: "统一管理所有第三方授权，随时查看权限范围并一键撤销。" },
];

const stats = [
  { v: "99.99%", l: "服务可用性" },
  { v: "128ms", l: "平均授权耗时" },
  { v: "2,400+", l: "接入应用" },
  { v: "180万", l: "活跃通行证" },
];

export default function Landing() {
  const nav = useNavigate();
  const { user } = useStore();

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#05060f]">
      <Starfield density={0.00018} />
      <div className="aurora left-[-10%] top-[-15%] h-[480px] w-[560px] bg-indigo-600/25" />
      <div className="aurora right-[-12%] top-[15%] h-[420px] w-[480px] bg-cyan-500/15" />
      <div className="aurora bottom-[-20%] left-[25%] h-[380px] w-[600px] bg-violet-700/20" />
      <div className="bg-grid absolute inset-0" />

      {/* Nav */}
      <nav className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
        <BrandMark />
        <div className="hidden items-center gap-8 text-sm text-slate-400 md:flex">
          <a href="#features" className="transition hover:text-white">能力</a>
          <a href="#developers" className="transition hover:text-white">开发者</a>
          <span className="cursor-pointer transition hover:text-white">文档</span>
        </div>
        <div className="flex items-center gap-3">
          {user ? (
            <GlowButton onClick={() => nav("/console")}>进入控制台</GlowButton>
          ) : (
            <>
              <Link to="/login" className="rounded-xl px-4 py-2 text-sm text-slate-300 transition hover:text-white">登录</Link>
              <GlowButton onClick={() => nav("/register")}>创建通行证</GlowButton>
            </>
          )}
        </div>
      </nav>

      {/* Hero */}
      <header className="relative z-10 mx-auto max-w-6xl px-6 pb-24 pt-14 text-center md:pt-20">
        <motion.div
          initial={{ opacity: 0, scale: 0.7 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="mx-auto mb-10 flex justify-center"
        >
          <div className="animate-float">
            <Logo size={104} ring />
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2, duration: 0.7 }}>
          <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-indigo-400/25 bg-indigo-500/10 px-4 py-1.5 text-xs text-indigo-300">
            <Sparkles size={13} />
            {BRAND.full} · 面向星辰的身份基础设施
          </div>
          <h1 className="mx-auto max-w-3xl text-4xl font-bold leading-tight tracking-tight text-white md:text-6xl">
            以一枚<span className="text-aurora">辰星通行证</span>
            <br />
            连接整个天穹生态
          </h1>
          <p className="mx-auto mt-6 max-w-xl text-base leading-relaxed text-slate-400">
            辰星认证中枢提供企业级 OAuth 2.1 / OpenID Connect 身份服务——
            安全登录、细粒度授权、统一账户管理，让每一次连接都值得信赖。
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4, duration: 0.7 }}
          className="mt-10 flex flex-wrap items-center justify-center gap-4"
        >
          <GlowButton className="px-8 py-3 text-base" onClick={() => nav("/register")}>
            免费创建通行证 <ArrowRight size={16} className="ml-1 inline" />
          </GlowButton>
          <GhostButton className="px-8 py-3 text-base" onClick={() => nav("/oauth/authorize?client=星图笔记&from=demo")}>
            体验授权流程
          </GhostButton>
        </motion.div>

        {/* stats */}
        <motion.div
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.7, duration: 0.8 }}
          className="mx-auto mt-20 grid max-w-3xl grid-cols-2 gap-px overflow-hidden rounded-2xl border border-white/5 bg-white/5 md:grid-cols-4"
        >
          {stats.map((s) => (
            <div key={s.l} className="bg-[#0a0c1cdd] px-6 py-5">
              <div className="text-2xl font-bold text-aurora">{s.v}</div>
              <div className="mt-1 text-xs text-slate-500">{s.l}</div>
            </div>
          ))}
        </motion.div>
      </header>

      <div className="line-shimmer relative z-10 mx-auto h-px max-w-4xl" />

      {/* Features */}
      <section id="features" className="relative z-10 mx-auto max-w-6xl px-6 py-24">
        <div className="mb-12 text-center">
          <h2 className="text-3xl font-bold text-white">为信任而生的认证中枢</h2>
          <p className="mt-3 text-sm text-slate-500">安全、极速、可观测——三位一体的身份服务</p>
        </div>
        <div className="grid gap-5 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ delay: i * 0.08, duration: 0.5 }}
              className="glass group rounded-2xl p-6 transition-all hover:-translate-y-1 hover:border-indigo-400/35 hover:shadow-[0_10px_40px_-10px_rgba(109,92,255,0.35)]"
            >
              <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br from-indigo-500/25 to-cyan-500/15 text-indigo-300 transition group-hover:text-cyan-300">
                {f.icon}
              </div>
              <h3 className="mb-2 font-semibold text-white">{f.title}</h3>
              <p className="text-sm leading-relaxed text-slate-500">{f.desc}</p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Developer strip */}
      <section id="developers" className="relative z-10 mx-auto max-w-6xl px-6 pb-24">
        <div className="glass relative overflow-hidden rounded-3xl p-8 md:p-12">
          <div className="aurora -right-20 -top-24 h-72 w-72 bg-cyan-500/20" />
          <div className="relative grid items-center gap-10 md:grid-cols-2">
            <div>
              <div className="mb-4 flex items-center gap-2 text-xs font-medium tracking-widest text-cyan-300">
                <Zap size={14} /> FOR DEVELOPERS
              </div>
              <h3 className="text-2xl font-bold text-white md:text-3xl">
                让你的应用接入
                <br />
                <span className="text-aurora">「使用辰星通行证登录」</span>
              </h3>
              <p className="mt-4 text-sm leading-relaxed text-slate-400">
                在控制台申请 API 权限、创建 OAuth 应用，即可获得 Client ID 与密钥。
                内置授权测试台，无需后端即可完整演练授权码流程。
              </p>
              <div className="mt-6 flex flex-wrap gap-3">
                <GlowButton onClick={() => nav(user ? "/console/developer" : "/login")}>
                  申请 API 权限
                </GlowButton>
                <GhostButton onClick={() => nav(user ? "/console/playground" : "/login")}>
                  打开测试台
                </GhostButton>
              </div>
            </div>
            <div className="code-block rounded-2xl p-5 text-[12.5px] leading-relaxed">
              <div className="mb-3 flex gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-400/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-400/80" />
              </div>
              <pre className="overflow-x-auto text-slate-400">
{`GET `}<span className="text-cyan-300">https://auth.skyvault.star/oauth/authorize</span>{`
  ?client_id=`}<span className="text-indigo-300">svs_live_9f2Ka7XmQ4</span>{`
  &redirect_uri=`}<span className="text-indigo-300">https://yourapp.com/cb</span>{`
  &response_type=`}<span className="text-emerald-300">code</span>{`
  &scope=`}<span className="text-emerald-300">openid profile email</span>{`
  &code_challenge=`}<span className="text-slate-500">…S256</span>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-white/5">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-6 py-8 text-xs text-slate-600 md:flex-row">
          <div className="flex items-center gap-2.5">
            <Logo size={22} />
            <span>© 2026 {BRAND.name} · {BRAND.platform}</span>
          </div>
          <div className="flex items-center gap-6">
            <span className="flex items-center gap-1.5"><Lock size={12} /> 隐私政策</span>
            <span className="flex items-center gap-1.5"><Globe2 size={12} /> 服务条款</span>
            <span>ICP 备 2026-Star 号</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
