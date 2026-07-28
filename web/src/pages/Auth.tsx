import { useState, ReactNode } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  Mail, LockKeyhole, User, ArrowRight, ShieldCheck,
  CheckCircle2, Loader2, Fingerprint, Globe, QrCode,
} from "lucide-react";
import Starfield from "../components/Starfield";
import { Logo, GlowButton, Field } from "../components/ui";
import { BRAND, Account, randomId } from "../data/mock";
import { useStore } from "../store";

/* ---------- shared shell ---------- */
function AuthShell({ children, side }: { children: ReactNode; side: ReactNode }) {
  return (
    <div className="relative flex min-h-screen overflow-hidden bg-[#05060f]">
      <Starfield density={0.00016} />
      <div className="aurora left-[-15%] top-[-10%] h-[500px] w-[500px] bg-indigo-600/25" />
      <div className="aurora bottom-[-15%] right-[-10%] h-[420px] w-[460px] bg-cyan-500/15" />

      {/* Left brand panel */}
      <div className="relative z-10 hidden w-[44%] flex-col justify-between border-r border-white/5 p-12 lg:flex">
        <Link to="/" className="flex items-center gap-3">
          <Logo size={36} />
          <div>
            <div className="font-semibold text-white">{BRAND.name}</div>
            <div className="text-[10px] tracking-[0.25em] text-indigo-300/60">{BRAND.platform}</div>
          </div>
        </Link>
        <div>
          <div className="mb-8 flex justify-start">
            <div className="animate-float"><Logo size={88} ring /></div>
          </div>
          {side}
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-600">
          <ShieldCheck size={14} className="text-indigo-400/70" />
          端到端加密 · OAuth 2.1 · OpenID Connect 认证服务
        </div>
      </div>

      {/* Right form */}
      <div className="relative z-10 flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-[400px]">
          <Link to="/" className="mb-8 flex items-center justify-center gap-2.5 lg:hidden">
            <Logo size={34} />
            <span className="font-semibold text-white">{BRAND.full}</span>
          </Link>
          {children}
        </div>
      </div>
    </div>
  );
}

function SocialRow() {
  return (
    <>
      <div className="my-6 flex items-center gap-3 text-[11px] text-slate-600">
        <div className="h-px flex-1 bg-white/8" /> 或通过以下方式 <div className="h-px flex-1 bg-white/8" />
      </div>
      <div className="grid grid-cols-3 gap-3">
        {[<Fingerprint key="g" size={17} />, <Globe key="c" size={17} />, <QrCode key="q" size={17} />].map((ic, i) => (
          <button key={i} className="glass-soft flex cursor-pointer items-center justify-center rounded-xl py-2.5 text-slate-400 transition hover:border-indigo-400/40 hover:text-white">
            {ic}
          </button>
        ))}
      </div>
    </>
  );
}

/* ---------- Login ---------- */
export function Login() {
  const nav = useNavigate();
  const { login, accounts } = useStore();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = () => {
    setBusy(true);
    setTimeout(() => {
      const acc = accounts.find((a) => a.email === email) ?? accounts[0];
      login(acc);
      nav("/console");
    }, 900);
  };

  return (
    <AuthShell
      side={
        <>
          <h2 className="text-3xl font-bold leading-snug text-white">
            欢迎回到<br /><span className="text-aurora">辰星认证中枢</span>
          </h2>
          <p className="mt-4 max-w-sm text-sm leading-relaxed text-slate-500">
            登录你的辰星通行证，管理授权应用、开发者密钥与账户安全。
          </p>
        </>
      }
    >
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-3xl p-8">
        <h1 className="text-xl font-bold text-white">登录通行证</h1>
        <p className="mt-1.5 text-xs text-slate-500">演示环境 · 无需真实凭据，直接点击登录即可</p>

        <div className="mt-6 space-y-4">
          <Field
            label="邮箱 / 辰星 ID" icon={<Mail size={15} />} placeholder="you@skyvault.star"
            value={email} onChange={(e) => setEmail(e.target.value)}
          />
          <Field label="密码" icon={<LockKeyhole size={15} />} type="password" placeholder="••••••••" />
          <div className="flex items-center justify-between text-xs">
            <label className="flex cursor-pointer items-center gap-2 text-slate-500">
              <input type="checkbox" defaultChecked className="accent-indigo-500" /> 记住此设备
            </label>
            <span className="cursor-pointer text-indigo-400 hover:text-indigo-300">忘记密码？</span>
          </div>
          <GlowButton className="w-full py-3" onClick={submit} disabled={busy}>
            {busy ? <Loader2 size={16} className="mx-auto animate-spin" /> : <>登录 <ArrowRight size={15} className="ml-1 inline" /></>}
          </GlowButton>
        </div>

        <SocialRow />

        <p className="mt-6 text-center text-xs text-slate-500">
          还没有通行证？{" "}
          <Link to="/register" className="font-medium text-indigo-400 hover:text-indigo-300">立即创建</Link>
        </p>
      </motion.div>
    </AuthShell>
  );
}

/* ---------- Register ---------- */
export function Register() {
  const nav = useNavigate();
  const { login, addAccount } = useStore();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phase, setPhase] = useState<"form" | "creating" | "done">("form");

  const submit = () => {
    setPhase("creating");
    setTimeout(() => setPhase("done"), 1400);
    setTimeout(() => {
      const acc: Account = {
        id: randomId("a_"),
        name: name || "新晋辰星",
        email: email || "newstar@skyvault.star",
        color: "from-amber-400 to-rose-500",
        role: "user",
        uid: `SV-${Math.floor(88000000 + Math.random() * 99999)}`,
      };
      addAccount(acc);
      login(acc);
      nav("/console");
    }, 2600);
  };

  return (
    <AuthShell
      side={
        <>
          <h2 className="text-3xl font-bold leading-snug text-white">
            铸造你的<br /><span className="text-aurora">辰星通行证</span>
          </h2>
          <p className="mt-4 max-w-sm text-sm leading-relaxed text-slate-500">
            一个账户，连接天穹辰星全系产品与 2,400+ 生态应用。注册即刻生效，永久免费。
          </p>
          <ul className="mt-6 space-y-2.5 text-sm text-slate-400">
            {["统一身份，跨应用单点登录", "细粒度授权，随时一键撤销", "开发者控制台与 API 权限申请"].map((t) => (
              <li key={t} className="flex items-center gap-2.5">
                <CheckCircle2 size={15} className="text-emerald-400" /> {t}
              </li>
            ))}
          </ul>
        </>
      }
    >
      <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="glass relative overflow-hidden rounded-3xl p-8">
        <AnimatePresence mode="wait">
          {phase === "form" && (
            <motion.div key="form" exit={{ opacity: 0, y: -12 }}>
              <h1 className="text-xl font-bold text-white">创建辰星通行证</h1>
              <p className="mt-1.5 text-xs text-slate-500">演示环境 · 填写任意信息即可完成注册</p>
              <div className="mt-6 space-y-4">
                <Field label="昵称" icon={<User size={15} />} placeholder="你的星际代号" value={name} onChange={(e) => setName(e.target.value)} />
                <Field label="邮箱" icon={<Mail size={15} />} placeholder="you@skyvault.star" value={email} onChange={(e) => setEmail(e.target.value)} />
                <Field label="密码" icon={<LockKeyhole size={15} />} type="password" placeholder="至少 8 位，含字母与数字" />
                <label className="flex cursor-pointer items-start gap-2 text-[11px] leading-relaxed text-slate-500">
                  <input type="checkbox" defaultChecked className="mt-0.5 accent-indigo-500" />
                  <span>我已阅读并同意《辰星通行证服务条款》与《隐私政策》</span>
                </label>
                <GlowButton className="w-full py-3" onClick={submit}>
                  创建通行证 <ArrowRight size={15} className="ml-1 inline" />
                </GlowButton>
              </div>
              <SocialRow />
              <p className="mt-6 text-center text-xs text-slate-500">
                已有通行证？ <Link to="/login" className="font-medium text-indigo-400 hover:text-indigo-300">直接登录</Link>
              </p>
            </motion.div>
          )}

          {phase !== "form" && (
            <motion.div
              key="done" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
              className="flex flex-col items-center py-14 text-center"
            >
              {phase === "creating" ? (
                <>
                  <div className="relative mb-6">
                    <div className="orbit-ring absolute -inset-5 animate-[spin_3s_linear_infinite]" />
                    <Logo size={64} />
                  </div>
                  <div className="text-sm font-medium text-white">正在为你点亮一颗辰星…</div>
                  <div className="mt-2 text-xs text-slate-500">生成唯一辰星 ID 与安全密钥</div>
                </>
              ) : (
                <>
                  <motion.div initial={{ scale: 0 }} animate={{ scale: 1 }} transition={{ type: "spring", stiffness: 260 }}>
                    <CheckCircle2 size={64} className="mb-5 text-emerald-400" />
                  </motion.div>
                  <div className="text-lg font-semibold text-white">通行证铸造完成</div>
                  <div className="mt-2 text-xs text-slate-500">正在跳转至你的控制台…</div>
                </>
              )}
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </AuthShell>
  );
}
