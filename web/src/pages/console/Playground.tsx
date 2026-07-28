import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Rocket, Check, Loader2, XCircle, RefreshCw, FlaskConical, Link2,
} from "lucide-react";
import { GlowButton, GhostButton, PageFade, Badge } from "../../components/ui";
import { SCOPES, randomId } from "../../data/mock";
import { useStore } from "../../store";

type StepState = "pending" | "active" | "done";

export default function Playground() {
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const { clients, user } = useStore();

  const code = sp.get("code");
  const error = sp.get("error");
  const backClient = sp.get("client");

  const [clientIdx, setClientIdx] = useState(0);
  const [picked, setPicked] = useState<string[]>(["openid", "profile", "email"]);
  const client = clients[Math.min(clientIdx, clients.length - 1)];

  const [steps, setSteps] = useState<StepState[]>(["pending", "pending", "pending"]);
  const accessToken = useMemo(() => "eyJhbGciOiJSUzI1NiJ9." + randomId("") + "." + randomId(""), [code]);

  useEffect(() => {
    if (!code) return;
    setSteps(["done", "active", "pending"]);
    const t1 = setTimeout(() => setSteps(["done", "done", "active"]), 1300);
    const t2 = setTimeout(() => setSteps(["done", "done", "done"]), 2400);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [code]);

  const toggle = (id: string) =>
    setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p, id]));

  const authorizeUrl = `https://auth.skyvault.star/oauth/authorize\n  ?client_id=${client?.clientId ?? "svs_live_xxx"}\n  &redirect_uri=${encodeURIComponent(client?.redirectUri ?? "")}\n  &response_type=code\n  &scope=${picked.join("+")}\n  &state=xyz_9f3k\n  &code_challenge=E9Mel…&code_challenge_method=S256`;

  const launch = () => {
    nav(`/oauth/authorize?client=${encodeURIComponent(client?.name ?? "测试应用")}&from=playground&scope=${encodeURIComponent(picked.join(" "))}`);
  };

  const reset = () => {
    setSp({});
    setSteps(["pending", "pending", "pending"]);
  };

  const StepIcon = ({ s }: { s: StepState }) =>
    s === "done" ? (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-400"><Check size={13} /></span>
    ) : s === "active" ? (
      <span className="flex h-6 w-6 items-center justify-center rounded-full bg-indigo-500/15 text-indigo-300"><Loader2 size={13} className="animate-spin" /></span>
    ) : (
      <span className="h-6 w-6 rounded-full border border-white/10" />
    );

  return (
    <PageFade>
      <div className="mb-6">
        <h1 className="flex items-center gap-2.5 text-xl font-bold text-white">
          <FlaskConical size={20} className="text-cyan-300" /> OAuth 测试台
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          无需后端，在浏览器中完整演练 OAuth 2.1 授权码 + PKCE 流程
        </p>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* ---- config ---- */}
        <div className="glass rounded-3xl p-6">
          <div className="mb-4 text-sm font-semibold text-slate-200">① 配置授权请求</div>

          <div className="mb-4">
            <div className="mb-2 text-xs text-slate-500">选择 OAuth 客户端</div>
            <div className="flex flex-wrap gap-2">
              {clients.map((c, i) => (
                <button
                  key={c.id}
                  onClick={() => setClientIdx(i)}
                  className={`cursor-pointer rounded-xl border px-3.5 py-2 text-xs font-medium transition ${
                    i === clientIdx
                      ? "border-indigo-400/60 bg-indigo-500/15 text-white"
                      : "border-white/8 text-slate-500 hover:border-white/20 hover:text-slate-300"
                  }`}
                >
                  {c.name}
                </button>
              ))}
            </div>
          </div>

          <div className="mb-4">
            <div className="mb-2 text-xs text-slate-500">Scopes</div>
            <div className="flex flex-wrap gap-1.5">
              {SCOPES.map((s) => (
                <button
                  key={s.id}
                  onClick={() => toggle(s.id)}
                  className={`cursor-pointer rounded-lg border px-2.5 py-1.5 font-mono text-[11px] transition ${
                    picked.includes(s.id)
                      ? "border-cyan-400/50 bg-cyan-500/12 text-cyan-300"
                      : "border-white/8 text-slate-600 hover:text-slate-400"
                  }`}
                >
                  {s.id}
                </button>
              ))}
            </div>
          </div>

          <div className="mb-5">
            <div className="mb-2 flex items-center gap-1.5 text-xs text-slate-500">
              <Link2 size={11} /> 授权请求 URL
            </div>
            <pre className="code-block overflow-x-auto rounded-xl p-4 text-[11.5px] leading-relaxed text-slate-400">
              <span className="text-emerald-400">GET</span> <span className="text-cyan-300">{authorizeUrl}</span>
            </pre>
          </div>

          <GlowButton className="w-full py-3" onClick={launch}>
            <Rocket size={15} className="mr-1.5 inline" /> 发起授权测试
          </GlowButton>
          <p className="mt-3 text-center text-[11px] text-slate-600">
            将跳转至真实的账号选择与授权确认页面，完成后带授权码返回
          </p>
        </div>

        {/* ---- result ---- */}
        <div className="glass rounded-3xl p-6">
          <div className="mb-4 flex items-center justify-between">
            <div className="text-sm font-semibold text-slate-200">② 回调与令牌交换</div>
            {(code || error) && (
              <button onClick={reset} className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-500 transition hover:text-white">
                <RefreshCw size={12} /> 重置
              </button>
            )}
          </div>

          {error ? (
            <div className="flex flex-col items-center py-14 text-center">
              <XCircle size={40} className="mb-4 text-rose-400" />
              <div className="text-sm font-medium text-white">用户取消了授权</div>
              <pre className="code-block mt-4 rounded-lg px-4 py-2 text-xs text-rose-300">error=access_denied&state=xyz_9f3k</pre>
              <GhostButton className="mt-6" onClick={reset}>重新测试</GhostButton>
            </div>
          ) : !code ? (
            <div className="flex flex-col items-center py-16 text-center">
              <motion.div
                animate={{ y: [0, -8, 0] }} transition={{ repeat: Infinity, duration: 2.4 }}
                className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-indigo-500/10 text-indigo-300"
              >
                <Rocket size={24} />
              </motion.div>
              <div className="text-sm text-slate-400">等待授权回调…</div>
              <div className="mt-1.5 text-xs text-slate-600">点击左侧「发起授权测试」开始</div>
            </div>
          ) : (
            <div className="space-y-4">
              {/* step 1 */}
              <div className="flex gap-3.5">
                <StepIcon s={steps[0]} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-slate-200">收到授权码 <Badge tone="green">302 回调</Badge></div>
                  <pre className="code-block mt-2 overflow-x-auto rounded-lg px-3.5 py-2.5 text-[11px] text-cyan-300">
{`${client?.redirectUri ?? ""}\n  ?code=${code}&state=xyz_9f3k`}
                  </pre>
                </div>
              </div>

              {/* step 2 */}
              <div className="flex gap-3.5">
                <StepIcon s={steps[1]} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-slate-200">交换访问令牌</div>
                  {steps[1] !== "pending" && (
                    <pre className="code-block mt-2 overflow-x-auto rounded-lg px-3.5 py-2.5 text-[11px] leading-relaxed text-slate-400">
<span className="text-emerald-400">POST</span> /oauth/token{"\n"}grant_type=<span className="text-indigo-300">authorization_code</span>{"\n"}code=<span className="text-cyan-300">{code}</span>{"\n"}code_verifier=<span className="text-slate-500">dBjftJeZ…</span>
                    </pre>
                  )}
                  {steps[1] === "done" && (
                    <motion.pre
                      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                      className="code-block mt-2 overflow-x-auto rounded-lg px-3.5 py-2.5 text-[11px] leading-relaxed"
                    >
<span className="text-slate-500">{"{"}</span>{"\n"}  <span className="text-indigo-300">"access_token"</span>: <span className="text-cyan-300">"{accessToken.slice(0, 34)}…"</span>,{"\n"}  <span className="text-indigo-300">"token_type"</span>: <span className="text-emerald-300">"Bearer"</span>,{"\n"}  <span className="text-indigo-300">"expires_in"</span>: <span className="text-amber-300">3600</span>,{"\n"}  <span className="text-indigo-300">"scope"</span>: <span className="text-emerald-300">"{picked.join(" ")}"</span>{"\n"}<span className="text-slate-500">{"}"}</span>
                    </motion.pre>
                  )}
                </div>
              </div>

              {/* step 3 */}
              <div className="flex gap-3.5">
                <StepIcon s={steps[2]} />
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] font-medium text-slate-200">获取用户信息 /userinfo</div>
                  {steps[2] === "done" && user && (
                    <motion.pre
                      initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
                      className="code-block mt-2 overflow-x-auto rounded-lg px-3.5 py-2.5 text-[11px] leading-relaxed"
                    >
<span className="text-slate-500">{"{"}</span>{"\n"}  <span className="text-indigo-300">"sub"</span>: <span className="text-cyan-300">"{user.uid}"</span>,{"\n"}  <span className="text-indigo-300">"name"</span>: <span className="text-cyan-300">"{user.name}"</span>,{"\n"}  <span className="text-indigo-300">"email"</span>: <span className="text-cyan-300">"{user.email}"</span>,{"\n"}  <span className="text-indigo-300">"email_verified"</span>: <span className="text-amber-300">true</span>{"\n"}<span className="text-slate-500">{"}"}</span>
                    </motion.pre>
                  )}
                </div>
              </div>

              {steps[2] === "done" && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.96 }} animate={{ opacity: 1, scale: 1 }}
                  className="flex items-center gap-2.5 rounded-2xl border border-emerald-400/25 bg-emerald-500/8 px-4 py-3 text-sm text-emerald-300"
                >
                  <Check size={16} /> 端到端流程验证成功 — {backClient ?? client?.name} 已通过辰星通行证完成认证
                </motion.div>
              )}
            </div>
          )}
        </div>
      </div>
    </PageFade>
  );
}
