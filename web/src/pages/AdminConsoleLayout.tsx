import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { LogOut, Mail, Settings, ShieldCheck } from "lucide-react";
import { api, AdminProfile, ApiError, errorMessage } from "../api";
import { Badge, Logo } from "../components/ui";
import { BRAND } from "../data/mock";
import { cn } from "../utils/cn";

const NAV = [{ to: "/admin-console/settings", label: "邮件设置", icon: <Mail size={17} /> }];

export default function AdminConsoleLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const [admin, setAdmin] = useState<AdminProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.adminMe().then((profile) => {
      if (active) setAdmin(profile);
    }).catch((value) => {
      if (!active) return;
      if (value instanceof ApiError && value.status === 401) navigate("/login?return_to=%2Fadmin-console", { replace: true });
      else if (value instanceof ApiError && value.status === 403) navigate("/console", { replace: true });
      else setError(errorMessage(value));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [navigate]);

  const logout = async () => {
    try { await api.logout(); } finally { navigate("/", { replace: true }); }
  };

  if (loading) return <div className="flex min-h-screen items-center justify-center bg-[#05060f] text-sm text-slate-500">正在验证管理员 Session…</div>;
  if (!admin) return <div className="flex min-h-screen items-center justify-center bg-[#05060f] p-6 text-center"><div className="glass max-w-md rounded-3xl p-8"><ShieldCheck size={30} className="mx-auto text-amber-300" /><h1 className="mt-4 text-lg font-semibold text-white">无法加载管理权限</h1><p className="mt-2 text-xs leading-6 text-slate-500">{error ?? "请使用管理员身份登录。"}</p><Link to="/login?return_to=%2Fadmin-console" className="mt-6 inline-block rounded-xl bg-indigo-500 px-5 py-2.5 text-sm font-semibold text-white">返回通行证登录</Link></div></div>;

  return (
    <div className="relative flex min-h-screen bg-[#05060f]">
      <div className="aurora right-[-10%] top-[-15%] h-[400px] w-[500px] bg-indigo-600/12" />
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 flex-col border-r border-white/6 bg-[#07081566] backdrop-blur-xl lg:flex">
        <Link to="/admin-console/settings" className="flex items-center gap-2.5 px-5 py-5">
          <Logo size={30} />
          <div className="leading-tight"><div className="text-sm font-semibold text-white">{BRAND.name}</div><div className="text-[9.5px] tracking-[0.2em] text-indigo-300/60">管理控制台</div></div>
        </Link>
        <div className="mx-3 mb-2 rounded-xl border border-amber-400/15 bg-amber-500/5 px-3 py-2.5 text-[11px] text-amber-200/80"><ShieldCheck size={13} className="mr-1.5 inline" />管理员模式</div>
        <nav className="flex-1 px-3 py-2">
          <div className="mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600">系统管理</div>
          {NAV.map((item) => <NavLink key={item.to} to={item.to} className={({ isActive }) => cn("flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] font-medium transition", isActive ? "bg-indigo-500/15 text-white" : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200")}>{({ isActive }) => <><span className={isActive ? "text-indigo-300" : ""}>{item.icon}</span>{item.label}</>}</NavLink>)}
        </nav>
        <div className="border-t border-white/6 p-3"><div className="flex items-center gap-2.5 rounded-xl p-2"><div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-amber-400 to-orange-600 text-xs font-semibold text-white">{(admin.username ?? "A").slice(0, 1).toUpperCase()}</div><div className="min-w-0 flex-1"><div className="truncate text-xs font-medium text-white">{admin.username ?? "管理员"}</div><div className="truncate text-[10px] text-slate-500">{admin.role}</div></div><button onClick={() => void logout()} title="退出管理后台" className="rounded-lg p-1.5 text-slate-500 transition hover:bg-rose-500/10 hover:text-rose-400"><LogOut size={15} /></button></div></div>
      </aside>
      <div className="relative z-10 flex-1 lg:pl-64"><header className="sticky top-0 z-20 flex items-center gap-3 border-b border-white/6 bg-[#05060fcc] px-5 py-3.5 backdrop-blur-xl md:px-8"><Settings size={16} className="text-indigo-300" /><span className="text-xs text-slate-400">管理控制台</span><span className="text-slate-700">/</span><span className="text-xs text-slate-200">{location.pathname.endsWith("settings") ? "邮件设置" : ""}</span><Badge tone="amber">{admin.role}</Badge></header><main className="p-5 md:p-8"><Outlet context={admin} /></main></div>
    </div>
  );
}
