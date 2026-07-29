import { useNavigate } from "react-router-dom";
import { ArrowRight, Code2, FlaskConical, Plug, ShieldCheck, UserRound } from "lucide-react";
import { Badge, PageFade, PageHeader, Section, Stat } from "../../components/ui";
import { useStore } from "../../store";
import { formatDate } from "../../api";

const SHORTCUTS = [
  { icon: <Code2 size={16} />, title: "接入应用", desc: "注册 OAuth Client 并获取凭据", to: "/console/developer" },
  { icon: <FlaskConical size={16} />, title: "授权测试", desc: "验证授权码 + PKCE 流程", to: "/console/playground" },
  { icon: <UserRound size={16} />, title: "通行证资料", desc: "更新资料、密码与登录会话", to: "/console/profile" },
  { icon: <Plug size={16} />, title: "已授权应用", desc: "查看第三方访问范围", to: "/console/connections" },
];

export default function Overview() {
  const navigate = useNavigate();
  const { user, clients, sessions } = useStore();
  if (!user) return null;

  const activeClients = clients.filter((client) => client.status === "active").length;
  const dailyUsed = clients.reduce((sum, client) => sum + client.quota.daily_used, 0);

  return (
    <PageFade>
      <PageHeader
        title={`欢迎回来，${user.name}`}
        description={
          <>
            {user.email} · 当前会话有效至 {formatDate(user.current_session_expires_at)}
          </>
        }
        actions={<Badge tone={user.status === "active" ? "green" : "amber"}>{user.status === "active" ? "账户正常" : user.status}</Badge>}
      />

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="接入应用" value={String(clients.length)} sub={`${activeClients} 个启用中`} />
        <Stat label="今日授权调用" value={dailyUsed.toLocaleString()} sub="所有应用合计" />
        <Stat label="活跃会话" value={String(sessions.length)} sub="含当前设备" />
        <Stat label="账户角色" value={user.role === "owner" ? "所有者" : user.role === "admin" ? "管理员" : "用户"} />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Section title="快捷入口">
          <div className="grid gap-2">
            {SHORTCUTS.map((item) => (
              <button
                key={item.to}
                onClick={() => navigate(item.to)}
                className="group flex cursor-pointer items-center gap-3 rounded-lg border border-hairline px-3.5 py-3 text-left transition-colors hover:border-slate-600 hover:bg-white/[0.02]"
              >
                <span className="text-slate-500 group-hover:text-indigo-400">{item.icon}</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-[13px] font-medium text-slate-200">{item.title}</span>
                  <span className="block text-[11px] text-slate-500">{item.desc}</span>
                </span>
                <ArrowRight size={14} className="text-slate-600 group-hover:text-slate-400" />
              </button>
            ))}
          </div>
        </Section>

        <Section title="会话安全">
          <div className="space-y-4 text-xs leading-relaxed text-slate-400">
            <div className="flex items-start gap-2.5">
              <ShieldCheck size={15} className="mt-0.5 shrink-0 text-emerald-400" />
              <p>
                登录状态保存在 HttpOnly Cookie 中，前端读取不到会话密钥。所有写操作都会附带 CSRF 令牌校验。
              </p>
            </div>
            <p>
              修改密码会立即撤销全部历史会话。如果发现陌生设备，可在
              <button onClick={() => navigate("/console/profile")} className="mx-1 cursor-pointer text-indigo-400 hover:text-indigo-300">
                通行证资料
              </button>
              中单独撤销。
            </p>
          </div>
        </Section>
      </div>
    </PageFade>
  );
}
