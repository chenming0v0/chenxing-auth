import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, ArrowLeftRight, Check, ChevronDown, Loader2, Lock, ShieldCheck } from "lucide-react";
import { Avatar, GhostButton, Logo } from "../components/ui";
import { api, errorMessage, PendingAuthorization } from "../api";
import { SCOPE_MAP } from "../data/constants";
import { useStore } from "../store";

type Phase = "consent" | "granting" | "done";

/** Decorative starfield — a handful of twinkling dots behind the card. */
function Starfield() {
  const stars = useMemo(
    () =>
      Array.from({ length: 70 }, () => ({
        left: `${(Math.random() * 100).toFixed(2)}%`,
        top: `${(Math.random() * 100).toFixed(2)}%`,
        delay: `${(Math.random() * 3.4).toFixed(2)}s`,
        scale: (0.5 + Math.random() * 1.3).toFixed(2),
      })),
    [],
  );
  return (
    <div aria-hidden className="pointer-events-none absolute inset-0 overflow-hidden">
      {stars.map((star, index) => (
        <span
          key={index}
          className="absolute h-0.5 w-0.5 rounded-full bg-slate-300/60 animate-[twinkle_3.4s_ease-in-out_infinite]"
          style={{ left: star.left, top: star.top, animationDelay: star.delay, transform: `scale(${star.scale})` }}
        />
      ))}
    </div>
  );
}

export default function OAuthConsent() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { user } = useStore();
  const requestId = params.get("request_id");
  const [pending, setPending] = useState<PendingAuthorization | null>(null);
  const [phase, setPhase] = useState<Phase>("consent");
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!requestId) {
      setError("缺少授权请求参数。");
      return;
    }
    if (!user) {
      navigate(`/login?request_id=${encodeURIComponent(requestId)}`, { replace: true });
      return;
    }
    void api.pendingAuthorization(requestId).then(setPending).catch((value) => setError(errorMessage(value)));
  }, [requestId, user, navigate]);

  const decide = async (decision: "approve" | "deny") => {
    if (!requestId) return;
    setBusy(decision);
    setError(null);
    try {
      const result = await api.decideAuthorization(requestId, decision);
      if (decision === "deny") {
        window.location.assign(result.redirect_to);
        return;
      }
      // Approve: play the grant animation, then hand off to the client callback.
      setPhase("granting");
      setTimeout(() => setPhase("done"), 1500);
      setTimeout(() => window.location.assign(result.redirect_to), 2300);
    } catch (value) {
      setError(errorMessage(value));
      setBusy(null);
    }
  };

  const clientInitial = pending?.client_name?.slice(0, 1).toUpperCase() ?? "?";

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-app p-4">
      <Starfield />
      <div className="aurora left-[8%] top-[-18%] h-[420px] w-[520px] bg-indigo-600/15" />
      <div className="aurora right-[4%] bottom-[-22%] h-[380px] w-[460px] bg-cyan-500/10" />

      <motion.div
        layout
        initial={{ opacity: 0, y: 20, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="glass relative z-10 w-full max-w-[880px] overflow-hidden rounded-[28px] shadow-2xl shadow-black/60"
      >
        <div className="flex items-center gap-3 border-b border-hairline px-7 py-4">
          <Logo size={26} />
          <span className="text-[15px] text-slate-200">使用辰星通行证登录</span>
          {pending && (
            <span className="ml-auto hidden items-center gap-1.5 text-[11px] text-slate-500 sm:flex">
              <Lock size={11} /> {pending.redirect_host}
            </span>
          )}
        </div>

        {!pending && !error && (
          <div className="flex items-center justify-center py-28">
            <Loader2 size={22} className="animate-spin text-slate-500" />
          </div>
        )}

        {error && !pending && (
          <div className="flex flex-col items-center px-6 py-20 text-center">
            <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-rose-500/10 text-rose-400">
              <AlertTriangle size={20} />
            </div>
            <h1 className="text-base font-semibold text-white">无法加载授权请求</h1>
            <p className="mt-2 max-w-sm text-xs leading-relaxed text-slate-500">{error}</p>
            <GhostButton className="mt-6" onClick={() => navigate("/console")}>返回控制台</GhostButton>
          </div>
        )}

        <AnimatePresence mode="wait">
          {pending && user && phase === "consent" && (
            <motion.div
              key="consent"
              initial={{ opacity: 0, x: 24 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.3 }}
              className="grid gap-10 px-7 py-10 md:grid-cols-2 md:px-10 md:py-12"
            >
              <div>
                <div className="mb-7 flex items-center gap-4">
                  <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-2xl font-semibold text-white shadow-lg shadow-indigo-900/50">
                    {clientInitial}
                  </div>
                  <motion.div animate={{ x: [0, 6, 0] }} transition={{ repeat: Infinity, duration: 1.6 }} className="text-indigo-400">
                    <ArrowLeftRight size={18} />
                  </motion.div>
                  <Logo size={48} />
                </div>

                <h1 className="text-[26px] font-normal leading-snug text-slate-100 md:text-[32px]">
                  {pending.client_name} 请求访问
                  <br />你的辰星通行证
                </h1>

                <div className="mt-6 inline-flex items-center gap-2.5 rounded-full border border-hairline px-2.5 py-1.5 pr-4">
                  <Avatar name={user.name} color={user.color} size="sm" />
                  <span className="min-w-0 leading-tight">
                    <span className="block truncate text-[13px] text-slate-200">{user.name}</span>
                    <span className="block truncate text-[11px] text-slate-500">{user.email}</span>
                  </span>
                </div>
              </div>

              <div>
                <div className="mb-4 text-[13px] font-medium tracking-wide text-slate-400">该应用将获得以下权限：</div>
                <div className="space-y-1 rounded-2xl border border-hairline bg-white/[0.025] p-2">
                  {pending.scopes.map((scope, index) => {
                    const known = SCOPE_MAP.get(scope);
                    return (
                      <motion.div
                        key={scope}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.07 * index }}
                        className="flex items-start gap-3 rounded-xl px-3 py-2.5 transition hover:bg-white/[0.035]"
                      >
                        <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${known ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400"}`}>
                          {known ? <Check size={12} /> : <AlertTriangle size={11} />}
                        </span>
                        <div className="min-w-0">
                          <div className="text-[13.5px] font-medium text-slate-200">{known?.consent ?? "该应用声明的访问范围"}</div>
                          <div className="mt-0.5 font-mono text-[11px] text-slate-500">{scope}</div>
                        </div>
                      </motion.div>
                    );
                  })}
                </div>

                <div className="mt-5 flex items-start gap-2.5 rounded-xl bg-indigo-500/[0.08] px-4 py-3 text-xs leading-relaxed text-slate-500">
                  <ShieldCheck size={15} className="mt-0.5 shrink-0 text-indigo-400" />
                  <span>
                    请确认你信任 {pending.client_name}。你可以随时在
                    <span className="text-indigo-400"> 控制台 → 授权管理 </span>中撤销此授权。
                  </span>
                </div>

                {error && (
                  <div className="mt-4 rounded-lg border border-rose-500/25 bg-rose-500/[0.07] px-3.5 py-3 text-xs leading-relaxed text-rose-200">
                    {error}
                  </div>
                )}

                <div className="mt-7 flex items-center justify-end gap-3">
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void decide("deny")}
                    className="cursor-pointer rounded-full px-6 py-2.5 text-sm font-medium text-indigo-400 transition hover:bg-indigo-500/10 disabled:opacity-50"
                  >
                    {busy === "deny" ? "取消中…" : "取消"}
                  </button>
                  <button
                    type="button"
                    disabled={busy !== null}
                    onClick={() => void decide("approve")}
                    className="btn-glow inline-flex cursor-pointer items-center gap-1.5 rounded-full px-8 py-2.5 text-sm font-semibold text-white"
                  >
                    {busy === "approve" ? <Loader2 size={15} className="animate-spin" /> : "允许"}
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {pending && (phase === "granting" || phase === "done") && (
            <motion.div
              key="grant"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center px-8 py-20 text-center"
            >
              <div className="mb-8 flex items-center gap-8">
                <Logo size={56} />
                <div className="relative h-px w-36 overflow-hidden bg-white/10">
                  <motion.div
                    className="absolute inset-y-0 w-14 bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
                    animate={{ x: [-60, 160] }}
                    transition={{ repeat: Infinity, duration: 1.1, ease: "linear" }}
                  />
                </div>
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-xl font-semibold text-white">
                  {clientInitial}
                </div>
              </div>

              {phase === "granting" ? (
                <>
                  <div className="flex items-center gap-2 text-sm font-medium text-slate-200">
                    <Loader2 size={15} className="animate-spin text-indigo-400" /> 正在签发授权码…
                  </div>
                  <div className="mt-2 text-xs text-slate-500">加密通道已建立 · PKCE 校验通过</div>
                </>
              ) : (
                <>
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: "spring", stiffness: 260 }}
                    className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-400"
                  >
                    <Check size={24} />
                  </motion.div>
                  <div className="text-sm font-medium text-slate-100">授权成功，正在返回 {pending.client_name}</div>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      <div className="relative z-10 mt-4 flex w-full max-w-[880px] items-center justify-between px-2 text-xs text-slate-500">
        <span className="flex items-center gap-1.5 rounded px-2 py-1.5">简体中文 <ChevronDown size={13} /></span>
        <div className="flex gap-1">
          {["帮助", "隐私权", "条款"].map((label) => (
            <span key={label} className="rounded px-3 py-1.5">{label}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
