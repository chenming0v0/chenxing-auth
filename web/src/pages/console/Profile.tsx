import { motion } from "framer-motion";
import {
  Mail, Fingerprint, ShieldCheck, Smartphone, KeyRound,
  MapPin, Calendar, Copy, Check, Pencil,
} from "lucide-react";
import { useState } from "react";
import { Avatar, Badge, PageFade, GhostButton } from "../../components/ui";
import { useStore } from "../../store";

export default function Profile() {
  const { user } = useStore();
  const [copied, setCopied] = useState(false);
  if (!user) return null;

  const copy = () => {
    navigator.clipboard?.writeText(user.uid).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  const security = [
    { icon: <ShieldCheck size={16} />, title: "双因素验证", desc: "TOTP 验证器已绑定", status: "已开启", tone: "green" as const },
    { icon: <Smartphone size={16} />, title: "受信设备", desc: "3 台设备处于活跃状态", status: "3 台", tone: "cyan" as const },
    { icon: <KeyRound size={16} />, title: "通行密钥 Passkey", desc: "支持指纹 / 面容快捷登录", status: "2 个", tone: "indigo" as const },
    { icon: <Mail size={16} />, title: "恢复邮箱", desc: "re****@backup.star", status: "已验证", tone: "green" as const },
  ];

  return (
    <PageFade>
      <div className="grid gap-6 lg:grid-cols-3">
        {/* identity card */}
        <motion.div
          initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
          className="glass relative overflow-hidden rounded-3xl p-7 lg:col-span-1"
        >
          <div className="aurora -right-14 -top-16 h-52 w-52 bg-indigo-500/25" />
          <div className="relative flex flex-col items-center pt-4 text-center">
            <div className="relative">
              <div className="orbit-ring absolute -inset-3 animate-[spin_18s_linear_infinite]" />
              <Avatar name={user.name} color={user.color} size="xl" />
            </div>
            <h1 className="mt-5 text-xl font-bold text-white">{user.name}</h1>
            <div className="mt-1 text-sm text-slate-500">{user.email}</div>
            <div className="mt-3 flex gap-2">
              <Badge tone="indigo">{user.role === "owner" ? "超级管理员" : user.role === "admin" ? "管理员" : "认证用户"}</Badge>
              <Badge tone="green">已实名</Badge>
            </div>

            <button
              onClick={copy}
              className="code-block mt-6 flex w-full cursor-pointer items-center justify-between rounded-xl px-4 py-3 text-left transition hover:border-indigo-400/40"
            >
              <div>
                <div className="text-[10px] uppercase tracking-widest text-slate-600">辰星 ID</div>
                <div className="mt-0.5 font-mono text-sm text-cyan-300">{user.uid}</div>
              </div>
              {copied ? <Check size={15} className="text-emerald-400" /> : <Copy size={15} className="text-slate-500" />}
            </button>

            <div className="mt-5 grid w-full grid-cols-2 gap-3 text-left text-xs text-slate-500">
              <div className="flex items-center gap-2"><Calendar size={13} className="text-indigo-400/70" /> 2024-12 注册</div>
              <div className="flex items-center gap-2"><MapPin size={13} className="text-indigo-400/70" /> 上海 · 中国</div>
            </div>

            <GhostButton className="mt-6 w-full">
              <Pencil size={13} className="mr-1.5 inline" /> 编辑公开资料
            </GhostButton>
          </div>
        </motion.div>

        <div className="space-y-6 lg:col-span-2">
          {/* public profile visible to apps */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }} className="glass rounded-3xl p-7">
            <div className="mb-1 flex items-center gap-2 text-sm font-semibold text-white">
              <Fingerprint size={16} className="text-indigo-300" /> 第三方应用可见信息
            </div>
            <p className="mb-5 text-xs text-slate-500">当你授权 profile / email Scope 时，应用将读取以下字段</p>
            <div className="grid gap-3 sm:grid-cols-2">
              {[
                ["sub（唯一标识）", user.uid],
                ["name（昵称）", user.name],
                ["email", user.email],
                ["email_verified", "true"],
                ["locale", "zh-CN"],
                ["zoneinfo", "Asia/Shanghai"],
              ].map(([k, v]) => (
                <div key={k} className="rounded-xl border border-white/6 bg-white/[0.02] px-4 py-3">
                  <div className="text-[10px] font-medium uppercase tracking-wider text-slate-600">{k}</div>
                  <div className="mt-1 truncate font-mono text-[13px] text-slate-200">{v}</div>
                </div>
              ))}
            </div>
          </motion.div>

          {/* security */}
          <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }} className="glass rounded-3xl p-7">
            <div className="mb-5 flex items-center gap-2 text-sm font-semibold text-white">
              <ShieldCheck size={16} className="text-emerald-400" /> 安全防护
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {security.map((s) => (
                <div key={s.title} className="flex items-center gap-3.5 rounded-2xl border border-white/6 bg-white/[0.02] p-4 transition hover:border-indigo-400/25">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-indigo-500/12 text-indigo-300">{s.icon}</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-[13px] font-medium text-white">{s.title}</div>
                    <div className="truncate text-[11px] text-slate-500">{s.desc}</div>
                  </div>
                  <Badge tone={s.tone}>{s.status}</Badge>
                </div>
              ))}
            </div>
          </motion.div>
        </div>
      </div>
    </PageFade>
  );
}
