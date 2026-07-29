import { Link } from "react-router-dom";
import { ArrowRight, Code2, Fingerprint, LockKeyhole, ShieldCheck, Settings } from "lucide-react";
import Starfield from "../components/Starfield";
import { BrandMark, GlowButton, GhostButton } from "../components/ui";
import { BRAND } from "../data/mock";
import { useStore } from "../store";

export default function Landing() {
  const { user, loading } = useStore();
  return <div className="relative min-h-screen overflow-hidden bg-[#05060f]"><Starfield density={0.00014} /><div className="aurora left-[8%] top-[-18%] h-[520px] w-[520px] bg-indigo-600/20" /><div className="aurora bottom-[-20%] right-[4%] h-[460px] w-[520px] bg-cyan-500/12" />
    <header className="relative z-10 mx-auto flex max-w-7xl items-center justify-between px-6 py-6 lg:px-10"><BrandMark compact /><div className="flex items-center gap-3"><Link to="/admin-console/login" title="管理员入口" className="rounded-lg p-2 text-slate-600 transition hover:bg-white/5 hover:text-indigo-300"><Settings size={15} /></Link>{loading ? <span className="text-xs text-slate-600">正在检查会话</span> : user ? <><span className="hidden text-xs text-slate-400 sm:inline">{user.name}</span><Link to="/console"><GhostButton className="px-4 py-2">进入控制台 <ArrowRight size={14} className="ml-1 inline" /></GhostButton></Link></> : <><Link to="/login" className="text-sm text-slate-400 transition hover:text-white">登录</Link><Link to="/register"><GlowButton className="px-4 py-2">创建通行证</GlowButton></Link></>}</div></header>
    <main className="relative z-10 mx-auto max-w-7xl px-6 pb-20 pt-16 lg:px-10 lg:pt-28"><div className="max-w-3xl"><div className="mb-6 inline-flex items-center gap-2 rounded-full border border-cyan-400/15 bg-cyan-400/5 px-3 py-1.5 text-xs text-cyan-200"><span className="h-1.5 w-1.5 rounded-full bg-cyan-300" /> 辰星通行证 · 统一身份服务</div><h1 className="text-5xl font-bold leading-[1.08] tracking-tight text-white md:text-7xl">让每一次登录<br /><span className="text-aurora">都值得信任</span></h1><p className="mt-7 max-w-xl text-base leading-8 text-slate-400 md:text-lg">安全地管理你的身份、授权应用和 OAuth 接入项目。清晰知道谁能访问什么，也能随时收回权限。</p><div className="mt-9 flex flex-wrap gap-3"><Link to={user ? "/console" : "/register"}><GlowButton className="px-6 py-3">{user ? "打开控制台" : "开始使用"} <ArrowRight size={16} className="ml-1 inline" /></GlowButton></Link><Link to="/login"><GhostButton className="px-6 py-3">已有账号，登录</GhostButton></Link></div></div>
      <div className="mt-24 grid gap-4 border-t border-white/8 pt-8 md:grid-cols-3"><Feature icon={<Fingerprint />} title="一个身份" text="使用同一套辰星通行证访问接入平台。" /><Feature icon={<ShieldCheck />} title="明确授权" text="每个应用的 Scope 都在授权前清楚呈现。" /><Feature icon={<Code2 />} title="标准接入" text="基于 OAuth 2.0 和 OpenID Connect 构建。" /></div>
      <div className="mt-20 flex flex-col items-start gap-5 border-l border-indigo-400/25 pl-5 text-sm text-slate-500"><div className="flex items-center gap-2"><LockKeyhole size={14} className="text-indigo-300" /> Session 使用 HttpOnly Cookie 与 CSRF 双重绑定</div><div>由 {BRAND.full} 提供 · 发行者地址固定于服务配置</div></div>
    </main>
  </div>;
}

function Feature({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) { return <div className="flex gap-3.5"><div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-indigo-500/12 text-indigo-300">{icon}</div><div><div className="text-sm font-semibold text-white">{title}</div><div className="mt-1 text-xs leading-5 text-slate-500">{text}</div></div></div>; }
