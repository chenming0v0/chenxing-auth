import { useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  UserCircle2, ChevronDown, ShieldCheck, ArrowLeftRight,
  Check, AlertTriangle, Loader2, Lock,
} from "lucide-react";
import Starfield from "../components/Starfield";
import { Logo, Avatar } from "../components/ui";
import { SCOPES, Account, randomId } from "../data/mock";
import { useStore } from "../store";

type Phase = "choose" | "consent" | "granting" | "done";

export default function OAuthFlow() {
  const nav = useNavigate();
  const [sp] = useSearchParams();
  const { accounts, user } = useStore();

  const clientName = sp.get("client") || "星图笔记";
  const from = sp.get("from") || "demo"; // playground | demo
  const scopeIds = useMemo(() => {
    const s = sp.get("scope");
    return s ? s.split(" ").filter(Boolean) : ["openid", "profile", "email"];
  }, [sp]);
  const scopes = SCOPES.filter((s) => scopeIds.includes(s.id));

  const [phase, setPhase] = useState<Phase>("choose");
  const [selected, setSelected] = useState<Account | null>(user);
  const code = useMemo(() => randomId("AC-"), []);

  const pick = (a: Account) => {
    setSelected(a);
    setTimeout(() => setPhase("consent"), 220);
  };

  const grant = () => {
    setPhase("granting");
    setTimeout(() => setPhase("done"), 1600);
    setTimeout(() => {
      if (from === "playground") {
        nav(`/console/playground?code=${code}&state=xyz_9f3k&client=${encodeURIComponent(clientName)}`);
      } else {
        nav("/");
      }
    }, 3000);
  };

  const cancel = () => {
    if (from === "playground") nav(`/console/playground?error=access_denied`);
    else nav(-1);
  };

  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center overflow-hidden bg-[#0b0c14] p-4">
      <Starfield density={0.00008} className="opacity-60" />
      <div className="aurora left-[10%] top-[-20%] h-[400px] w-[500px] bg-indigo-600/12" />

      {/* Card */}
      <motion.div
        layout
        initial={{ opacity: 0, y: 20, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="relative z-10 w-full max-w-[880px] overflow-hidden rounded-[28px] border border-white/8 bg-[#131318]/95 shadow-2xl shadow-black/60 backdrop-blur-xl"
      >
        {/* header bar */}
        <div className="flex items-center gap-3 border-b border-white/6 px-7 py-4">
          <Logo size={26} />
          <span className="text-[15px] text-slate-200">使用辰星通行证登录</span>
          <span className="ml-auto hidden items-center gap-1.5 text-[11px] text-slate-500 sm:flex">
            <Lock size={11} /> auth.skyvault.star
          </span>
        </div>

        <AnimatePresence mode="wait">
          {/* ============ PHASE: choose account ============ */}
          {phase === "choose" && (
            <motion.div
              key="choose"
              initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.3 }}
              className="grid gap-10 px-7 py-10 md:grid-cols-2 md:px-10 md:py-14"
            >
              <div>
                <h1 className="text-[32px] font-normal leading-tight text-slate-100 md:text-[40px]">
                  选择账号
                </h1>
                <p className="mt-4 text-[15px] text-slate-400">
                  以继续前往 <span className="cursor-pointer font-medium text-indigo-400 hover:underline">{clientName}</span>
                </p>
              </div>

              <div>
                <div className="divide-y divide-white/6 border-y border-white/6">
                  {accounts.map((a, i) => (
                    <motion.button
                      key={a.id}
                      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.08 * i }}
                      onClick={() => pick(a)}
                      className="group flex w-full cursor-pointer items-center gap-4 px-2 py-3.5 text-left transition hover:bg-white/[0.045]"
                    >
                      <Avatar name={a.name} color={a.color} size="md" />
                      <div className="min-w-0">
                        <div className="truncate text-sm font-medium text-slate-100">{a.name}</div>
                        <div className="truncate text-[13px] text-slate-500">{a.email}</div>
                      </div>
                      <span className="ml-auto text-slate-600 opacity-0 transition group-hover:opacity-100">→</span>
                    </motion.button>
                  ))}
                  <button
                    onClick={() => nav("/login")}
                    className="flex w-full cursor-pointer items-center gap-4 px-2 py-3.5 text-left transition hover:bg-white/[0.045]"
                  >
                    <span className="flex h-10 w-10 items-center justify-center text-slate-400">
                      <UserCircle2 size={26} />
                    </span>
                    <span className="text-sm font-medium text-slate-100">使用其他账号</span>
                  </button>
                </div>

                <p className="mt-8 text-[13px] leading-relaxed text-slate-500">
                  在使用此应用之前，你可以查看 {clientName} 的
                  <span className="cursor-pointer text-indigo-400 hover:underline">《隐私权政策》</span>和
                  <span className="cursor-pointer text-indigo-400 hover:underline">《服务条款》</span>。
                </p>
              </div>
            </motion.div>
          )}

          {/* ============ PHASE: consent ============ */}
          {phase === "consent" && selected && (
            <motion.div
              key="consent"
              initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -24 }}
              transition={{ duration: 0.3 }}
              className="grid gap-10 px-7 py-10 md:grid-cols-2 md:px-10 md:py-12"
            >
              <div>
                {/* app ↔ hub visual */}
                <div className="mb-7 flex items-center gap-4">
                  <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-2xl text-white shadow-lg shadow-indigo-900/50">
                    {clientName.slice(0, 1)}
                  </div>
                  <motion.div
                    animate={{ x: [0, 6, 0] }} transition={{ repeat: Infinity, duration: 1.6 }}
                    className="text-indigo-400"
                  >
                    <ArrowLeftRight size={18} />
                  </motion.div>
                  <Logo size={48} />
                </div>

                <h1 className="text-[28px] font-normal leading-snug text-slate-100 md:text-[34px]">
                  {clientName} 请求访问
                  <br />你的辰星通行证
                </h1>

                <button
                  onClick={() => setPhase("choose")}
                  className="mt-6 flex cursor-pointer items-center gap-2.5 rounded-full border border-white/12 px-2.5 py-1.5 pr-4 transition hover:bg-white/5"
                >
                  <Avatar name={selected.name} color={selected.color} size="sm" />
                  <span className="text-[13px] text-slate-300">{selected.email}</span>
                  <ChevronDown size={14} className="text-slate-500" />
                </button>
              </div>

              <div>
                <div className="mb-4 text-[13px] font-medium tracking-wide text-slate-400">
                  该应用将获得以下权限：
                </div>
                <div className="space-y-1 rounded-2xl border border-white/8 bg-white/[0.025] p-2">
                  {scopes.map((s, i) => (
                    <motion.div
                      key={s.id}
                      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.07 * i }}
                      className="flex items-start gap-3 rounded-xl px-3 py-2.5 transition hover:bg-white/[0.035]"
                    >
                      <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${s.sensitive ? "bg-amber-500/15 text-amber-400" : "bg-emerald-500/15 text-emerald-400"}`}>
                        {s.sensitive ? <AlertTriangle size={11} /> : <Check size={12} />}
                      </span>
                      <div>
                        <div className="text-[13.5px] font-medium text-slate-200">{s.label}</div>
                        <div className="mt-0.5 text-xs leading-relaxed text-slate-500">{s.desc}</div>
                      </div>
                    </motion.div>
                  ))}
                </div>

                <div className="mt-5 flex items-start gap-2.5 rounded-xl bg-indigo-500/8 px-4 py-3 text-xs leading-relaxed text-slate-500">
                  <ShieldCheck size={15} className="mt-0.5 shrink-0 text-indigo-400" />
                  <span>
                    请确认你信任 {clientName}。你可以随时在
                    <span className="text-indigo-400"> 控制台 → 授权管理 </span>中撤销此授权。
                  </span>
                </div>

                <div className="mt-7 flex items-center justify-end gap-3">
                  <button
                    onClick={cancel}
                    className="cursor-pointer rounded-full px-6 py-2.5 text-sm font-medium text-indigo-400 transition hover:bg-indigo-500/10"
                  >
                    取消
                  </button>
                  <button
                    onClick={grant}
                    className="btn-glow cursor-pointer rounded-full px-8 py-2.5 text-sm font-semibold text-white"
                  >
                    允许
                  </button>
                </div>
              </div>
            </motion.div>
          )}

          {/* ============ PHASE: granting / done ============ */}
          {(phase === "granting" || phase === "done") && selected && (
            <motion.div
              key="grant"
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              className="flex flex-col items-center px-8 py-20 text-center"
            >
              <div className="relative mb-8 flex items-center gap-8">
                <Logo size={56} />
                <div className="relative h-px w-36 overflow-hidden bg-white/10">
                  <motion.div
                    className="absolute inset-y-0 w-14 bg-gradient-to-r from-transparent via-cyan-400 to-transparent"
                    animate={{ x: [-60, 160] }}
                    transition={{ repeat: Infinity, duration: 1.1, ease: "linear" }}
                  />
                </div>
                <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-600 text-xl text-white">
                  {clientName.slice(0, 1)}
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
                  <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 260 }}
                    className="mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-400">
                    <Check size={24} />
                  </motion.div>
                  <div className="text-sm font-medium text-slate-100">授权成功，正在返回 {clientName}</div>
                  <div className="code-block mt-4 rounded-lg px-4 py-2 text-xs text-cyan-300">
                    ?code={code}&state=xyz_9f3k
                  </div>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>

      {/* footer */}
      <div className="relative z-10 mt-4 flex w-full max-w-[880px] items-center justify-between px-2 text-xs text-slate-500">
        <button className="flex cursor-pointer items-center gap-1.5 rounded px-2 py-1.5 transition hover:bg-white/5">
          简体中文 <ChevronDown size={13} />
        </button>
        <div className="flex gap-1">
          {["帮助", "隐私权", "条款"].map((t) => (
            <span key={t} className="cursor-pointer rounded px-3 py-1.5 transition hover:bg-white/5">{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
