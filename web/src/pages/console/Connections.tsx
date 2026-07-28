import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Plug, ShieldOff, Clock, AlertTriangle, Sparkles } from "lucide-react";
import { Badge, Modal, GhostButton, PageFade } from "../../components/ui";
import { SCOPES, ConnectedApp } from "../../data/mock";
import { useStore } from "../../store";
import { useNavigate } from "react-router-dom";

export default function Connections() {
  const { connections, revoke } = useStore();
  const [target, setTarget] = useState<ConnectedApp | null>(null);
  const nav = useNavigate();

  const confirmRevoke = () => {
    if (target) revoke(target.id);
    setTarget(null);
  };

  return (
    <PageFade>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white">授权管理</h1>
          <p className="mt-1 text-sm text-slate-500">
            以下应用可通过辰星通行证访问你的账户 · 共 {connections.length} 个连接
          </p>
        </div>
        <GhostButton onClick={() => nav("/oauth/authorize?client=星轨日历&from=demo&scope=openid profile star.orbit")}>
          <Sparkles size={13} className="mr-1.5 inline" /> 模拟新授权
        </GhostButton>
      </div>

      {connections.length === 0 ? (
        <div className="glass flex flex-col items-center rounded-3xl py-20 text-center">
          <Plug size={36} className="mb-4 text-slate-600" />
          <div className="text-sm font-medium text-slate-300">暂无已授权的应用</div>
          <div className="mt-1.5 text-xs text-slate-600">当你使用辰星通行证登录第三方应用后，会显示在这里</div>
        </div>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <AnimatePresence>
            {connections.map((app, i) => (
              <motion.div
                key={app.id}
                layout
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.92, transition: { duration: 0.25 } }}
                transition={{ delay: i * 0.05 }}
                className="glass group rounded-3xl p-6 transition-all hover:border-indigo-400/30"
              >
                <div className="flex items-start gap-4">
                  <div className={`flex h-13 w-13 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br text-xl text-white shadow-lg ${app.color} h-12 w-12`}>
                    {app.icon}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <h3 className="truncate font-semibold text-white">{app.name}</h3>
                      <Badge tone="green">活跃</Badge>
                    </div>
                    <div className="mt-0.5 text-xs text-slate-500">{app.publisher} · {app.grantedAt} 授权</div>
                  </div>
                  <button
                    onClick={() => setTarget(app)}
                    className="cursor-pointer rounded-xl border border-white/8 px-3 py-1.5 text-xs font-medium text-slate-400 opacity-70 transition hover:border-rose-400/40 hover:bg-rose-500/10 hover:text-rose-300 group-hover:opacity-100"
                  >
                    <ShieldOff size={12} className="mr-1 inline" /> 撤销
                  </button>
                </div>

                <div className="mt-4 flex flex-wrap gap-1.5">
                  {app.scopes.map((sid) => {
                    const s = SCOPES.find((x) => x.id === sid);
                    return (
                      <span
                        key={sid}
                        title={s?.desc}
                        className={`rounded-lg border px-2 py-1 font-mono text-[10.5px] ${
                          s?.sensitive
                            ? "border-amber-400/25 bg-amber-500/8 text-amber-300"
                            : "border-indigo-400/20 bg-indigo-500/8 text-indigo-300"
                        }`}
                      >
                        {sid}
                      </span>
                    );
                  })}
                </div>

                <div className="mt-4 flex items-center gap-1.5 border-t border-white/6 pt-3.5 text-[11px] text-slate-600">
                  <Clock size={11} /> 最近使用：{app.lastUsed}
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}

      {/* revoke confirm */}
      <Modal open={!!target} onClose={() => setTarget(null)} title="撤销授权">
        {target && (
          <>
            <div className="mb-5 flex items-center gap-3.5 rounded-2xl border border-white/6 bg-white/[0.02] p-4">
              <div className={`flex h-11 w-11 items-center justify-center rounded-xl bg-gradient-to-br text-lg text-white ${target.color}`}>
                {target.icon}
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{target.name}</div>
                <div className="text-xs text-slate-500">{target.publisher}</div>
              </div>
            </div>
            <div className="mb-6 flex items-start gap-2.5 rounded-xl bg-amber-500/8 px-4 py-3 text-xs leading-relaxed text-amber-200/80">
              <AlertTriangle size={15} className="mt-0.5 shrink-0 text-amber-400" />
              撤销后，该应用的所有访问令牌与刷新令牌将立即失效，你需要重新授权才能继续使用该应用的辰星登录。
            </div>
            <div className="flex justify-end gap-3">
              <GhostButton onClick={() => setTarget(null)}>取消</GhostButton>
              <button
                onClick={confirmRevoke}
                className="cursor-pointer rounded-xl bg-gradient-to-r from-rose-500 to-red-600 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-rose-950/40 transition hover:brightness-110"
              >
                确认撤销
              </button>
            </div>
          </>
        )}
      </Modal>
    </PageFade>
  );
}
