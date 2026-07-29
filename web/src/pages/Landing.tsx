import { Link } from "react-router-dom";
import { ArrowRight, Code2, Fingerprint, LockKeyhole, Settings, ShieldCheck } from "lucide-react";
import { BrandMark, GhostButton, GlowButton } from "../components/ui";
import { BRAND } from "../data/mock";
import { useStore } from "../store";

const FEATURES = [
  { icon: <Fingerprint size={17} />, title: "一个身份", text: "同一套辰星通行证登录所有已接入的子项目。" },
  { icon: <ShieldCheck size={17} />, title: "明确授权", text: "应用请求的每个 Scope 都在确认前列清楚。" },
  { icon: <Code2 size={17} />, title: "标准协议", text: "OAuth 2.0 授权码 + PKCE，OpenID Connect 身份层。" },
];

export default function Landing() {
  const { user, loading } = useStore();

  return (
    <div className="relative min-h-screen overflow-hidden bg-app">
      <div className="aurora left-[10%] top-[-20%] h-[460px] w-[460px] bg-indigo-600/12" />

      <header className="relative z-10 mx-auto flex max-w-6xl items-center justify-between px-6 py-5">
        <BrandMark compact />
        <div className="flex items-center gap-2.5">
          <Link
            to="/admin-console/login"
            title="管理员入口"
            className="rounded-lg p-2 text-slate-600 transition-colors hover:bg-white/[0.04] hover:text-slate-300"
          >
            <Settings size={15} />
          </Link>
          {loading ? (
            <span className="text-xs text-slate-600">检查登录状态…</span>
          ) : user ? (
            <>
              <span className="hidden text-xs text-slate-400 sm:inline">{user.name}</span>
              <Link to="/console">
                <GhostButton className="px-4 py-2">进入控制台 <ArrowRight size={14} /></GhostButton>
              </Link>
            </>
          ) : (
            <>
              <Link to="/login" className="px-2 text-sm text-slate-400 transition-colors hover:text-white">
                登录
              </Link>
              <Link to="/register">
                <GlowButton className="px-4 py-2">创建通行证</GlowButton>
              </Link>
            </>
          )}
        </div>
      </header>

      <main className="relative z-10 mx-auto max-w-6xl px-6 pb-20 pt-14 lg:pt-24">
        <div className="max-w-2xl">
          <h1 className="text-4xl font-semibold leading-[1.12] tracking-tight text-white md:text-5xl">
            天穹辰星的<br />
            <span className="text-aurora">统一身份服务</span>
          </h1>
          <p className="mt-6 max-w-xl text-base leading-relaxed text-slate-400">
            管理你的身份、已授权的应用，以及作为开发者的 OAuth 接入项目。清楚知道谁能访问什么，也能随时收回。
          </p>
          <div className="mt-8 flex flex-wrap gap-2.5">
            <Link to={user ? "/console" : "/register"}>
              <GlowButton className="px-5 py-3">
                {user ? "打开控制台" : "创建通行证"} <ArrowRight size={15} />
              </GlowButton>
            </Link>
            {!user && (
              <Link to="/login">
                <GhostButton className="px-5 py-3">已有账号，登录</GhostButton>
              </Link>
            )}
          </div>
        </div>

        <div className="mt-20 grid gap-6 border-t border-hairline pt-8 md:grid-cols-3">
          {FEATURES.map((feature) => (
            <div key={feature.title} className="flex gap-3">
              <span className="mt-0.5 shrink-0 text-slate-500">{feature.icon}</span>
              <div>
                <div className="text-[13px] font-medium text-white">{feature.title}</div>
                <p className="mt-1 text-xs leading-relaxed text-slate-500">{feature.text}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-16 space-y-2 border-l border-hairline pl-4 text-xs text-slate-500">
          <div className="flex items-center gap-2">
            <LockKeyhole size={13} /> 会话使用 HttpOnly Cookie 与 CSRF 双重绑定
          </div>
          <div>由 {BRAND.full} 提供 · 发行者地址固定于服务配置</div>
        </div>
      </main>
    </div>
  );
}
