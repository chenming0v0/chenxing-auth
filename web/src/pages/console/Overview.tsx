import { useNavigate } from "react-router-dom";
import { Activity, ArrowUpRight, Code2, Fingerprint, Plug, ShieldCheck } from "lucide-react";
import { PageFade, Stat, Badge } from "../../components/ui";
import { useStore } from "../../store";
import { formatDate } from "../../api";

export default function Overview() {
  const nav = useNavigate();
  const { user, clients, sessions } = useStore();
  if (!user) return null;
  const quick = [
    { icon: <Fingerprint size={18} />, title: "通行证资料", desc: "更新公开身份信息", to: "/console/profile" },
    { icon: <Code2 size={18} />, title: "开发者应用", desc: `${clients.length} / 2 个 OAuth 项目`, to: "/console/developer" },
    { icon: <Plug size={18} />, title: "授权管理", desc: "查看接入与授权说明", to: "/console/connections" },
    { icon: <ShieldCheck size={18} />, title: "OAuth 测试台", desc: "验证授权码 + PKCE 流程", to: "/console/playground" },
  ];
  return <PageFade><div className="glass relative mb-6 overflow-hidden rounded-3xl p-7 md:p-8"><div className="aurora -right-16 -top-20 h-64 w-64 bg-indigo-500/25" /><div className="relative flex flex-wrap items-center gap-5"><div className={`flex h-20 w-20 items-center justify-center rounded-full bg-gradient-to-br text-2xl font-semibold text-white shadow-lg ${user.color}`}>{user.name.slice(0, 1).toUpperCase()}</div><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-3"><h1 className="text-2xl font-bold text-white">欢迎回来，{user.name}</h1><Badge tone="green">账户正常</Badge></div><p className="mt-1.5 text-sm text-slate-400">{user.email} · Session 有效至 {formatDate(user.current_session_expires_at)}</p></div></div></div>
    <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4"><Stat icon={<Code2 size={17} />} label="OAuth 项目" value={String(clients.length)} sub="最多 2 个" /><Stat icon={<Activity size={17} />} label="今日授权额度" value={clients.length ? `${clients.reduce((sum, client) => sum + client.quota.daily_used, 0).toLocaleString()}` : "0"} sub="按项目统计" /><Stat icon={<ShieldCheck size={17} />} label="活跃 Session" value={String(sessions.length)} /><Stat icon={<Fingerprint size={17} />} label="身份状态" value="正常" sub="可安全使用" /></div>
    <div className="grid gap-6 lg:grid-cols-5"><div className="lg:col-span-2"><h2 className="mb-3 text-sm font-semibold text-slate-300">快捷入口</h2><div className="grid gap-3">{quick.map((item) => <button key={item.to} onClick={() => nav(item.to)} className="glass group flex cursor-pointer items-center gap-4 rounded-2xl p-4 text-left transition-all hover:border-indigo-400/35 hover:bg-indigo-500/[0.06]"><span className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/12 text-indigo-300">{item.icon}</span><span className="flex-1"><span className="block text-sm font-medium text-white">{item.title}</span><span className="block text-xs text-slate-500">{item.desc}</span></span><ArrowUpRight size={15} className="text-slate-600 transition group-hover:text-indigo-300" /></button>)}</div></div><div className="lg:col-span-3"><h2 className="mb-3 text-sm font-semibold text-slate-300">当前状态</h2><div className="glass rounded-2xl p-6"><div className="flex items-start gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-300"><ShieldCheck size={17} /></span><div><div className="text-sm font-medium text-white">你的 Session 正在工作</div><p className="mt-1 text-xs leading-6 text-slate-500">登录 Cookie 由服务端管理，前端不会读取 Session 秘密。执行资料修改、应用创建等操作时会自动携带 CSRF 校验。</p></div></div></div></div></div>
  </PageFade>;
}
