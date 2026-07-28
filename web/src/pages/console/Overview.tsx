import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Plug, KeyRound, Activity, ShieldCheck, ArrowUpRight,
  FlaskConical, Code2, UserRound, Globe2, MonitorSmartphone,
} from "lucide-react";
import { Stat, Avatar, Badge, PageFade } from "../../components/ui";
import { useStore } from "../../store";

const activity = [
  { icon: <ShieldCheck size={14} />, tone: "text-emerald-400 bg-emerald-500/10", text: "通过「星图笔记」完成 OAuth 登录", time: "2 小时前", tag: "授权" },
  { icon: <KeyRound size={14} />, tone: "text-indigo-400 bg-indigo-500/10", text: "开发者应用「极光相册」刷新了访问令牌", time: "5 小时前", tag: "令牌" },
  { icon: <MonitorSmartphone size={14} />, tone: "text-cyan-400 bg-cyan-500/10", text: "新设备登录：Chrome · macOS · 上海", time: "昨天 21:44", tag: "安全" },
  { icon: <Plug size={14} />, tone: "text-amber-400 bg-amber-500/10", text: "撤销了「旧版日历」的全部授权", time: "3 天前", tag: "撤销" },
  { icon: <Globe2 size={14} />, tone: "text-violet-400 bg-violet-500/10", text: "API 权限申请「深空终端」进入审核", time: "5 天前", tag: "审核" },
];

export default function Overview() {
  const nav = useNavigate();
  const { user, connections, clients } = useStore();
  if (!user) return null;

  const quick = [
    { icon: <Plug size={18} />, title: "授权管理", desc: `${connections.length} 个应用已连接`, to: "/console/connections" },
    { icon: <Code2 size={18} />, title: "申请 API 权限", desc: "创建 OAuth 应用", to: "/console/developer" },
    { icon: <FlaskConical size={18} />, title: "OAuth 测试台", desc: "实时演练授权流程", to: "/console/playground" },
    { icon: <UserRound size={18} />, title: "通行证资料", desc: "查看公开身份信息", to: "/console/profile" },
  ];

  return (
    <PageFade>
      {/* welcome */}
      <div className="glass relative mb-6 overflow-hidden rounded-3xl p-7 md:p-8">
        <div className="aurora -right-16 -top-20 h-64 w-64 bg-indigo-500/25" />
        <div className="aurora -bottom-24 left-1/3 h-56 w-72 bg-cyan-500/12" />
        <div className="relative flex flex-wrap items-center gap-5">
          <Avatar name={user.name} color={user.color} size="xl" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-bold text-white">晚上好，{user.name}</h1>
              <Badge tone="green">通行证正常</Badge>
            </div>
            <p className="mt-1.5 text-sm text-slate-400">
              辰星 ID <span className="font-mono text-indigo-300">{user.uid}</span> · 已受
              <span className="text-cyan-300"> 双因素验证 </span>保护
            </p>
          </div>
          <div className="hidden text-right md:block">
            <div className="text-3xl font-bold text-aurora">98</div>
            <div className="text-xs text-slate-500">账户安全分</div>
          </div>
        </div>
      </div>

      {/* stats */}
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={<Plug size={17} />} label="已授权应用" value={String(connections.length)} sub="+1 本周" />
        <Stat icon={<Code2 size={17} />} label="开发者应用" value={String(clients.length)} />
        <Stat icon={<Activity size={17} />} label="30 天授权次数" value="1,284" sub="+18.6%" />
        <Stat icon={<ShieldCheck size={17} />} label="活跃令牌" value="7" />
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        {/* quick actions */}
        <div className="lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">快捷入口</h2>
          <div className="grid gap-3">
            {quick.map((q, i) => (
              <motion.button
                key={q.title}
                initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}
                onClick={() => nav(q.to)}
                className="glass group flex cursor-pointer items-center gap-4 rounded-2xl p-4 text-left transition-all hover:border-indigo-400/35 hover:bg-indigo-500/[0.06]"
              >
                <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500/12 text-indigo-300 transition group-hover:scale-110">
                  {q.icon}
                </span>
                <span className="flex-1">
                  <span className="block text-sm font-medium text-white">{q.title}</span>
                  <span className="block text-xs text-slate-500">{q.desc}</span>
                </span>
                <ArrowUpRight size={15} className="text-slate-600 transition group-hover:text-indigo-300" />
              </motion.button>
            ))}
          </div>
        </div>

        {/* activity */}
        <div className="lg:col-span-3">
          <h2 className="mb-3 text-sm font-semibold text-slate-300">最近动态</h2>
          <div className="glass rounded-2xl p-2">
            {activity.map((a, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.06 }}
                className="flex items-center gap-3.5 rounded-xl px-3.5 py-3 transition hover:bg-white/[0.03]"
              >
                <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${a.tone}`}>{a.icon}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px] text-slate-200">{a.text}</div>
                  <div className="text-[11px] text-slate-600">{a.time}</div>
                </div>
                <Badge tone="slate">{a.tag}</Badge>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </PageFade>
  );
}
