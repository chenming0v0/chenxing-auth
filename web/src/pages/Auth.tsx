import { FormEvent, ReactNode, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, Loader2, LockKeyhole, Mail, ShieldCheck, UserRound } from "lucide-react";
import Starfield from "../components/Starfield";
import { Field, GlowButton, Logo } from "../components/ui";
import { BRAND } from "../data/mock";
import { errorMessage } from "../api";
import { useStore } from "../store";

export function AuthShell({ children, title, subtitle }: { children: ReactNode; title: string; subtitle: string }) {
  return <div className="relative flex min-h-screen overflow-hidden bg-[#05060f]">
    <Starfield density={0.00016} />
    <div className="aurora left-[-15%] top-[-10%] h-[500px] w-[500px] bg-indigo-600/25" />
    <div className="aurora bottom-[-15%] right-[-10%] h-[420px] w-[460px] bg-cyan-500/15" />
    <div className="relative z-10 hidden w-[44%] flex-col justify-between border-r border-white/5 p-12 lg:flex">
      <Link to="/" className="flex items-center gap-3"><Logo size={36} /><div><div className="font-semibold text-white">{BRAND.name}</div><div className="text-[10px] tracking-[0.25em] text-indigo-300/60">{BRAND.platform}</div></div></Link>
      <div><div className="mb-8"><Logo size={88} ring /></div><h2 className="text-3xl font-bold leading-snug text-white">你的身份，由<br /><span className="text-aurora">辰星通行证守护</span></h2><p className="mt-4 max-w-sm text-sm leading-relaxed text-slate-500">统一登录、清晰授权、可撤销的账户安全控制。</p></div>
      <div className="flex items-center gap-2 text-xs text-slate-600"><ShieldCheck size={14} className="text-indigo-400/70" /> Session · CSRF · OpenID Connect</div>
    </div>
    <div className="relative z-10 flex flex-1 items-center justify-center p-6"><div className="w-full max-w-[420px]">
      <Link to="/" className="mb-8 flex items-center justify-center gap-2.5 lg:hidden"><Logo size={34} /><span className="font-semibold text-white">{BRAND.full}</span></Link>
      <div className="glass rounded-3xl p-8"><h1 className="text-xl font-bold text-white">{title}</h1><p className="mt-1.5 text-xs text-slate-500">{subtitle}</p>{children}</div>
    </div></div>
  </div>;
}

export function FormError({ value }: { value: string | null }) { return value ? <div role="alert" className="rounded-xl border border-rose-400/20 bg-rose-500/10 px-3.5 py-3 text-xs leading-relaxed text-rose-200">{value}</div> : null; }

export function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { login } = useStore();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => { event.preventDefault(); setBusy(true); setError(null); try { await login(email, password); const requestId = params.get("request_id"); navigate(requestId ? `/oauth/consent?request_id=${encodeURIComponent(requestId)}` : "/console"); } catch (value) { setError(errorMessage(value)); } finally { setBusy(false); } };
  return <AuthShell title="登录辰星通行证" subtitle={params.get("request_id") ? "登录后继续完成授权确认" : "使用你的身份进入认证中枢"}>
    <form className="mt-6 space-y-4" onSubmit={submit}>
      <FormError value={error} />
      <Field label="邮箱" icon={<Mail size={15} />} type="email" autoComplete="username" required placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} />
      <Field label="密码" icon={<LockKeyhole size={15} />} type="password" autoComplete="current-password" required placeholder="至少 10 个字符" value={password} onChange={(event) => setPassword(event.target.value)} />
      <GlowButton className="w-full py-3" type="submit" disabled={busy}>{busy ? <Loader2 size={16} className="mx-auto animate-spin" /> : <>登录 <ArrowRight size={15} className="ml-1 inline" /></>}</GlowButton>
    </form>
    <p className="mt-6 text-center text-xs text-slate-500">还没有通行证？ <Link to={`/register${params.get("request_id") ? `?request_id=${encodeURIComponent(params.get("request_id")!)}` : ""}`} className="font-medium text-indigo-400 hover:text-indigo-300">立即创建</Link></p>
  </AuthShell>;
}

export function Register() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { register } = useStore();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submit = async (event: FormEvent) => { event.preventDefault(); setBusy(true); setError(null); try { await register(email, password, name); const requestId = params.get("request_id"); navigate(requestId ? `/oauth/consent?request_id=${encodeURIComponent(requestId)}` : "/console"); } catch (value) { setError(errorMessage(value)); } finally { setBusy(false); } };
  return <AuthShell title="创建辰星通行证" subtitle="一个账号，连接所有接入辰星的应用"><form className="mt-6 space-y-4" onSubmit={submit}>
    <FormError value={error} />
    <Field label="显示名称（可选）" icon={<UserRound size={15} />} autoComplete="name" placeholder="你的昵称" value={name} onChange={(event) => setName(event.target.value)} />
    <Field label="邮箱" icon={<Mail size={15} />} type="email" autoComplete="email" required placeholder="you@example.com" value={email} onChange={(event) => setEmail(event.target.value)} />
    <Field label="密码" icon={<LockKeyhole size={15} />} type="password" autoComplete="new-password" required minLength={10} placeholder="至少 10 个字符" value={password} onChange={(event) => setPassword(event.target.value)} />
    <div className="rounded-xl border border-indigo-400/10 bg-indigo-500/5 px-3.5 py-3 text-xs leading-relaxed text-slate-500">密码会使用慢哈希保存。请使用 10 个字符以上的独立密码。</div>
    <GlowButton className="w-full py-3" type="submit" disabled={busy}>{busy ? <Loader2 size={16} className="mx-auto animate-spin" /> : <>创建并登录 <ArrowRight size={15} className="ml-1 inline" /></>}</GlowButton>
  </form><p className="mt-6 text-center text-xs text-slate-500">已有通行证？ <Link to={`/login${params.get("request_id") ? `?request_id=${encodeURIComponent(params.get("request_id")!)}` : ""}`} className="font-medium text-indigo-400 hover:text-indigo-300">返回登录</Link></p></AuthShell>;
}
