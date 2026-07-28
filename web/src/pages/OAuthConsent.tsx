import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AlertTriangle, ArrowLeftRight, Check, Loader2, Lock, ShieldCheck, X } from "lucide-react";
import Starfield from "../components/Starfield";
import { Avatar, Logo } from "../components/ui";
import { api, errorMessage, PendingAuthorization } from "../api";
import { useStore } from "../store";

const scopeCopy: Record<string, { title: string; description: string; sensitive?: boolean }> = {
  openid: { title: "身份标识", description: "用于识别你的辰星通行证" },
  profile: { title: "基本资料", description: "昵称与公开个人信息" },
  email: { title: "邮箱地址", description: "你的主邮箱地址" },
};

export default function OAuthConsent() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { user } = useStore();
  const requestId = params.get("request_id");
  const [pending, setPending] = useState<PendingAuthorization | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!requestId) { setError("缺少授权请求"); return; }
    if (!user) { navigate(`/login?request_id=${encodeURIComponent(requestId)}`, { replace: true }); return; }
    void api.pendingAuthorization(requestId).then(setPending).catch((value) => setError(errorMessage(value)));
  }, [requestId, user, navigate]);

  const decide = async (decision: "approve" | "deny") => {
    if (!requestId) return;
    setBusy(true); setError(null);
    try { const result = await api.decideAuthorization(requestId, decision); window.location.assign(result.redirect_to); }
    catch (value) { setError(errorMessage(value)); setBusy(false); }
  };

  return <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-[#0b0c14] p-4"><Starfield density={0.00008} className="opacity-60" /><div className="aurora left-[10%] top-[-20%] h-[400px] w-[500px] bg-indigo-600/12" />
    <div className="relative z-10 w-full max-w-[880px] overflow-hidden rounded-[28px] border border-white/8 bg-[#131318]/95 shadow-2xl shadow-black/60 backdrop-blur-xl"><div className="flex items-center gap-3 border-b border-white/6 px-7 py-4"><Logo size={26} /><span className="text-[15px] text-slate-200">使用辰星通行证登录</span><span className="ml-auto hidden items-center gap-1.5 text-[11px] text-slate-500 sm:flex"><Lock size={11} /> 当前认证中枢</span></div>
      {!pending && !error && <div className="flex items-center justify-center py-24"><Loader2 size={24} className="animate-spin text-indigo-300" /></div>}
      {error && <div className="flex flex-col items-center px-8 py-24 text-center"><X size={38} className="mb-4 text-rose-400" /><h1 className="text-lg font-semibold text-white">无法加载授权请求</h1><p className="mt-2 max-w-sm text-sm leading-6 text-slate-500">{error}</p><button className="mt-6 rounded-xl border border-white/10 px-5 py-2.5 text-sm text-slate-300 hover:bg-white/5" onClick={() => navigate("/console")}>返回控制台</button></div>}
      {pending && user && <div className="grid gap-10 px-7 py-10 md:grid-cols-2 md:px-10 md:py-12"><div><div className="mb-7 flex items-center gap-4"><div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-2xl text-white">{pending.client_name.slice(0, 1)}</div><ArrowLeftRight size={18} className="text-indigo-400" /><Logo size={48} /></div><h1 className="text-[28px] font-normal leading-snug text-slate-100 md:text-[34px]">{pending.client_name} 请求访问<br />你的辰星通行证</h1><div className="mt-6 inline-flex items-center gap-2.5 rounded-full border border-white/12 px-2.5 py-1.5 pr-4"><Avatar name={user.name} color={user.color} size="sm" /><span className="text-[13px] text-slate-300">{user.email}</span></div><div className="mt-6 text-xs text-slate-600">回调站点：<span className="font-mono text-slate-400">{pending.redirect_host}</span></div></div>
        <div><div className="mb-4 text-[13px] font-medium tracking-wide text-slate-400">该应用将获得以下权限：</div><div className="space-y-1 rounded-2xl border border-white/8 bg-white/[0.025] p-2">{pending.scopes.map((scope) => { const copy = scopeCopy[scope] ?? { title: scope, description: "应用声明的访问范围", sensitive: true }; return <div key={scope} className="flex items-start gap-3 rounded-xl px-3 py-2.5"><span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${copy.sensitive ? "bg-amber-500/15 text-amber-400" : "bg-emerald-500/15 text-emerald-400"}`}>{copy.sensitive ? <AlertTriangle size={11} /> : <Check size={12} />}</span><div><div className="text-[13.5px] font-medium text-slate-200">{copy.title} <span className="font-mono text-[11px] text-slate-500">({scope})</span></div><div className="mt-0.5 text-xs leading-relaxed text-slate-500">{copy.description}</div></div></div>; })}</div><div className="mt-5 flex items-start gap-2.5 rounded-xl bg-indigo-500/8 px-4 py-3 text-xs leading-relaxed text-slate-500"><ShieldCheck size={15} className="mt-0.5 shrink-0 text-indigo-400" />确认你信任这个应用。授权后仍可在账户安全设置中撤销相关 Session。</div>{error && <div role="alert" className="mt-4 rounded-xl border border-rose-400/20 bg-rose-500/10 px-4 py-3 text-xs text-rose-200">{error}</div>}<div className="mt-7 flex items-center justify-end gap-3"><button disabled={busy} onClick={() => void decide("deny")} className="flex cursor-pointer items-center gap-1.5 rounded-xl px-5 py-2.5 text-sm font-medium text-slate-400 hover:bg-white/5 hover:text-white"><X size={15} /> 拒绝</button><button disabled={busy} onClick={() => void decide("approve")} className="btn-glow flex cursor-pointer items-center gap-1.5 rounded-xl px-6 py-2.5 text-sm font-semibold text-white">{busy ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />} 允许</button></div></div>
      </div>}
    </div><div className="relative z-10 mt-4 text-xs text-slate-600">授权请求将在短时间后失效 · 你可以随时撤销访问</div>
  </div>;
}
