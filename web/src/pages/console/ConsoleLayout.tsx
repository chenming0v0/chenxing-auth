import { useEffect } from "react";
import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import {
  LayoutDashboard, UserRound, Plug, Code2, FlaskConical,
  Users, LogOut, Bell, Search, ChevronRight,
} from "lucide-react";
import { Logo, Avatar, Badge } from "../../components/ui";
import { BRAND } from "../../data/mock";
import { useStore } from "../../store";
import { cn } from "../../utils/cn";

const NAV = [
  { to: "/console", end: true, icon: <LayoutDashboard size={17} />, label: "总览", group: "个人中心" },
  { to: "/console/profile", icon: <UserRound size={17} />, label: "通行证资料", group: "个人中心" },
  { to: "/console/connections", icon: <Plug size={17} />, label: "授权管理", group: "个人中心" },
  { to: "/console/developer", icon: <Code2 size={17} />, label: "开发者应用", group: "开发者" },
  { to: "/console/playground", icon: <FlaskConical size={17} />, label: "OAuth 测试台", group: "开发者" },
  { to: "/console/users", icon: <Users size={17} />, label: "用户管理", group: "管理后台" },
];

export default function ConsoleLayout() {
  const nav = useNavigate();
  const loc = useLocation();
  const { user, logout, accounts, login } = useStore();

  useEffect(() => {
    if (!user) login(accounts[0]); // demo auto-login
  }, [user, login, accounts]);

  if (!user) return null;

  const current = NAV.find((n) => (n.end ? loc.pathname === n.to : loc.pathname.startsWith(n.to)));
  let lastGroup = "";

  return (
    <div className="relative flex min-h-screen bg-[#05060f]">
      <div className="aurora right-[-10%] top-[-15%] h-[400px] w-[500px] bg-indigo-600/12" />
      <div className="aurora bottom-[-15%] left-[20%] h-[350px] w-[500px] bg-cyan-600/8" />

      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-white/6 bg-[#07081566] backdrop-blur-xl lg:flex">
        <div
          className="flex cursor-pointer items-center gap-2.5 px-5 py-5"
          onClick={() => nav("/")}
        >
          <Logo size={30} />
          <div className="leading-tight">
            <div className="text-sm font-semibold text-white">{BRAND.name}</div>
            <div className="text-[9.5px] tracking-[0.2em] text-indigo-300/60">{BRAND.platform}</div>
          </div>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-2">
          {NAV.map((n) => {
            const header = n.group !== lastGroup ? n.group : null;
            lastGroup = n.group;
            return (
              <div key={n.to}>
                {header && (
                  <div className="mb-1.5 mt-5 px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-600 first:mt-1">
                    {header}
                  </div>
                )}
                <NavLink
                  to={n.to}
                  end={n.end}
                  className={({ isActive }) =>
                    cn(
                      "group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] font-medium transition-all",
                      isActive
                        ? "bg-gradient-to-r from-indigo-500/20 to-transparent text-white"
                        : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200"
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      {isActive && (
                        <motion.span layoutId="navpill" className="absolute inset-y-1.5 left-0 w-[3px] rounded-full bg-gradient-to-b from-indigo-400 to-cyan-400" />
                      )}
                      <span className={isActive ? "text-indigo-300" : ""}>{n.icon}</span>
                      {n.label}
                    </>
                  )}
                </NavLink>
              </div>
            );
          })}
        </nav>

        <div className="border-t border-white/6 p-3">
          <div className="flex items-center gap-2.5 rounded-xl p-2 transition hover:bg-white/[0.04]">
            <Avatar name={user.name} color={user.color} size="sm" />
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs font-medium text-white">{user.name}</div>
              <div className="truncate text-[10px] text-slate-500">{user.email}</div>
            </div>
            <button
              onClick={() => { logout(); nav("/"); }}
              title="退出登录"
              className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition hover:bg-rose-500/10 hover:text-rose-400"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="relative z-10 flex-1 lg:pl-60">
        {/* Topbar */}
        <header className="sticky top-0 z-20 flex items-center gap-4 border-b border-white/6 bg-[#05060fcc] px-5 py-3.5 backdrop-blur-xl md:px-8">
          <div className="flex items-center gap-2 text-xs text-slate-500 lg:hidden">
            <Logo size={24} />
          </div>
          <div className="hidden items-center gap-1.5 text-xs text-slate-500 sm:flex">
            控制台 <ChevronRight size={12} /> <span className="text-slate-300">{current?.label ?? "总览"}</span>
          </div>
          <div className="field ml-auto hidden w-64 items-center gap-2 rounded-xl px-3 py-1.5 md:flex">
            <Search size={13} className="text-slate-600" />
            <input placeholder="搜索应用、用户、密钥…" className="w-full bg-transparent text-xs text-white placeholder:text-slate-600 focus:outline-none" />
            <kbd className="rounded border border-white/10 px-1.5 text-[9px] text-slate-600">⌘K</kbd>
          </div>
          <button className="relative cursor-pointer rounded-xl p-2 text-slate-500 transition hover:bg-white/5 hover:text-white">
            <Bell size={16} />
            <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-cyan-400" />
          </button>
          <Badge tone="cyan">演示环境</Badge>
        </header>

        <main className="p-5 md:p-8">
          <Outlet />
        </main>
      </div>

      {/* Mobile bottom nav */}
      <div className="fixed inset-x-0 bottom-0 z-30 flex justify-around border-t border-white/8 bg-[#070815ee] py-2 backdrop-blur-xl lg:hidden">
        {NAV.map((n) => (
          <NavLink
            key={n.to} to={n.to} end={n.end}
            className={({ isActive }) => cn("flex flex-col items-center gap-1 rounded-lg px-3 py-1 text-[9px]", isActive ? "text-indigo-300" : "text-slate-600")}
          >
            {n.icon}
            {n.label}
          </NavLink>
        ))}
      </div>
    </div>
  );
}
