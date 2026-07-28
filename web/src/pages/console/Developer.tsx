import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Plus, Eye, EyeOff, Copy, Check, Trash2, Code2,
  Globe, BarChart3, KeyRound,
} from "lucide-react";
import { Badge, Modal, GlowButton, GhostButton, Field, PageFade } from "../../components/ui";
import { SCOPES, OAuthClient, randomId } from "../../data/mock";
import { useStore } from "../../store";

function SecretRow({ label, value, mono = true }: { label: string; value: string; mono?: boolean }) {
  const [show, setShow] = useState(false);
  const [copied, setCopied] = useState(false);
  const masked = value.slice(0, 8) + "•".repeat(18);

  const copy = () => {
    navigator.clipboard?.writeText(value).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  return (
    <div className="code-block flex items-center gap-2 rounded-xl px-3.5 py-2.5">
      <div className="min-w-0 flex-1">
        <div className="text-[9.5px] uppercase tracking-widest text-slate-600">{label}</div>
        <div className={`truncate text-[12.5px] text-cyan-300 ${mono ? "font-mono" : ""}`}>
          {show ? value : masked}
        </div>
      </div>
      <button onClick={() => setShow(!show)} className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition hover:text-white">
        {show ? <EyeOff size={13} /> : <Eye size={13} />}
      </button>
      <button onClick={copy} className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition hover:text-white">
        {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
      </button>
    </div>
  );
}

export default function Developer() {
  const { clients, addClient, removeClient } = useStore();
  const [open, setOpen] = useState(false);
  const [created, setCreated] = useState<OAuthClient | null>(null);
  const [name, setName] = useState("");
  const [uri, setUri] = useState("");
  const [picked, setPicked] = useState<string[]>(["openid", "profile"]);

  const toggle = (id: string) =>
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));

  const submit = () => {
    const c: OAuthClient = {
      id: randomId("c_"),
      name: name || "未命名应用",
      clientId: randomId("svs_live_"),
      secret: randomId("sk_") + randomId(""),
      redirectUri: uri || "https://example.com/callback",
      scopes: picked.length ? picked : ["openid"],
      status: "审核中",
      createdAt: new Date().toISOString().slice(0, 10),
      calls30d: 0,
    };
    addClient(c);
    setCreated(c);
    setName(""); setUri(""); setPicked(["openid", "profile"]);
  };

  return (
    <PageFade>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">开发者应用 · API 权限</h1>
          <p className="mt-1 text-sm text-slate-500">
            创建 OAuth 客户端，让你的项目接入「使用辰星通行证登录」
          </p>
        </div>
        <GlowButton onClick={() => setOpen(true)}>
          <Plus size={14} className="mr-1 inline" /> 申请新应用
        </GlowButton>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <AnimatePresence>
          {clients.map((c, i) => (
            <motion.div
              key={c.id}
              layout
              initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.94 }}
              transition={{ delay: i * 0.05 }}
              className="glass rounded-3xl p-6 transition hover:border-indigo-400/30"
            >
              <div className="mb-5 flex items-start gap-4">
                <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500/25 to-cyan-500/15 text-indigo-300">
                  <Code2 size={19} />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-white">{c.name}</h3>
                    <Badge tone={c.status === "已上线" ? "green" : c.status === "审核中" ? "amber" : "slate"}>{c.status}</Badge>
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">创建于 {c.createdAt}</div>
                </div>
                <button
                  onClick={() => removeClient(c.id)}
                  className="cursor-pointer rounded-xl p-2 text-slate-600 transition hover:bg-rose-500/10 hover:text-rose-400"
                  title="删除应用"
                >
                  <Trash2 size={15} />
                </button>
              </div>

              <div className="space-y-2.5">
                <SecretRow label="Client ID" value={c.clientId} />
                <SecretRow label="Client Secret" value={c.secret} />
                <div className="code-block flex items-center gap-2.5 rounded-xl px-3.5 py-2.5">
                  <Globe size={13} className="shrink-0 text-slate-600" />
                  <div className="min-w-0 flex-1">
                    <div className="text-[9.5px] uppercase tracking-widest text-slate-600">Redirect URI</div>
                    <div className="truncate font-mono text-[12.5px] text-slate-300">{c.redirectUri}</div>
                  </div>
                </div>
              </div>

              <div className="mt-4 flex flex-wrap gap-1.5">
                {c.scopes.map((s) => (
                  <span key={s} className="rounded-lg border border-indigo-400/20 bg-indigo-500/8 px-2 py-1 font-mono text-[10.5px] text-indigo-300">{s}</span>
                ))}
              </div>

              <div className="mt-4 flex items-center gap-1.5 border-t border-white/6 pt-3.5 text-[11px] text-slate-600">
                <BarChart3 size={11} /> 近 30 天调用 <span className="font-mono text-cyan-300">{c.calls30d.toLocaleString()}</span> 次
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* create modal */}
      <Modal open={open} onClose={() => { setOpen(false); setCreated(null); }} title={created ? "应用创建成功" : "申请 API 权限"} wide>
        {!created ? (
          <div className="space-y-4">
            <Field label="应用名称" placeholder="例如：极光相册" value={name} onChange={(e) => setName(e.target.value)} />
            <Field label="回调地址 Redirect URI" placeholder="https://yourapp.com/oauth/callback" value={uri} onChange={(e) => setUri(e.target.value)} />
            <div>
              <div className="mb-2 text-xs font-medium tracking-wide text-slate-400">申请权限范围（Scopes）</div>
              <div className="grid gap-2 sm:grid-cols-2">
                {SCOPES.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => toggle(s.id)}
                    className={`flex cursor-pointer items-start gap-2.5 rounded-xl border p-3 text-left transition ${
                      picked.includes(s.id)
                        ? "border-indigo-400/50 bg-indigo-500/12"
                        : "border-white/8 bg-white/[0.02] hover:border-white/16"
                    }`}
                  >
                    <span className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border text-[9px] ${
                      picked.includes(s.id) ? "border-indigo-400 bg-indigo-500 text-white" : "border-slate-600"
                    }`}>
                      {picked.includes(s.id) && <Check size={10} />}
                    </span>
                    <span>
                      <span className="block text-xs font-medium text-slate-200">{s.label}</span>
                      <span className="mt-0.5 block text-[10.5px] leading-relaxed text-slate-500">{s.desc}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
            <div className="flex justify-end gap-3 pt-2">
              <GhostButton onClick={() => setOpen(false)}>取消</GhostButton>
              <GlowButton onClick={submit}>提交申请</GlowButton>
            </div>
          </div>
        ) : (
          <div>
            <div className="mb-5 flex items-center gap-3 rounded-2xl border border-emerald-400/20 bg-emerald-500/8 px-4 py-3 text-sm text-emerald-300">
              <KeyRound size={16} /> 凭据已生成 — Client Secret 仅展示一次，请妥善保存
            </div>
            <div className="space-y-2.5">
              <SecretRow label="Client ID" value={created.clientId} />
              <SecretRow label="Client Secret" value={created.secret} />
            </div>
            <div className="mt-6 flex justify-end">
              <GlowButton onClick={() => { setOpen(false); setCreated(null); }}>完成</GlowButton>
            </div>
          </div>
        )}
      </Modal>
    </PageFade>
  );
}
