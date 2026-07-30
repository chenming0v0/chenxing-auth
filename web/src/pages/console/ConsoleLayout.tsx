import { useEffect } from "react";
import { NavLink, Outlet, useNavigate, useLocation } from "react-router-dom";
import { Code2, FlaskConical, LayoutDashboard, LogOut, Plug, UserRound } from "lucide-react";
import { Avatar, Logo } from "../../components/ui";
import { BRAND } from "../../data/constants";
import { useStore } from "../../store";
import { cn } from "../../utils/cn";

const NAV = [
  { to: "/console", end: true, icon: <LayoutDashboard size={16} />, label: "总览", group: "账户" },
  { to: "/console/profile", icon: <UserRound size={16} />, label: "通行证资料", group: "账户" },
  { to: "/console/connections", icon: <Plug size={16} />, label: "已授权应用", group: "账户" },
  { to: "/console/developer", icon: <Code2 size={16} />, label: "接入应用", group: "开发者" },
  { to: "/console/playground", icon: <FlaskConical size={16} />, label: "授权测试", group: "开发者" },
];

export default function ConsoleLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, loading, logout } = useStore();

  useEffect(() => {
    if (!loading && !user) navigate("/login", { replace: true });
  }, [loading, user, navigate]);

  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-app text-sm text-slate-500">
        正在加载控制台…
      </div>
    );
  }

  const current = NAV.find((item) =>
    item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)
  );
  let lastGroup = "";

  const signOut = () => { void logout(); navigate("/"); };

  return (
    <div className="flex min-h-screen bg-app">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r border-hairline bg-surface lg:flex">
        <button
          className="flex cursor-pointer items-center gap-2.5 px-4 py-4 text-left"
          onClick={() => navigate("/")}
        >
          <Logo size={26} />
          <span className="leading-tight">
            <span className="block text-[13px] font-semibold text-white">{BRAND.name}</span>
            <span className="block text-[10px] text-slate-500">{BRAND.platform}</span>
          </span>
        </button>

        <nav className="flex-1 overflow-y-auto px-2 py-2">
          {NAV.map((item) => {
            const header = item.group !== lastGroup ? item.group : null;
            lastGroup = item.group;
            return (
              <div key={item.to}>
                {header && (
                  <div className="mb-1 mt-4 px-2.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600 first:mt-1">
                    {header}
                  </div>
                )}
                <NavLink
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition-colors",
                      isActive
                        ? "bg-white/[0.06] font-medium text-white"
                        : "text-slate-400 hover:bg-white/[0.03] hover:text-slate-200"
                    )
                  }
                >
                  {({ isActive }) => (
                    <>
                      <span className={isActive ? "text-indigo-400" : "text-slate-500"}>{item.icon}</span>
                      {item.label}
                    </>
                  )}
                </NavLink>
              </div>
            );
          })}
        </nav>

        <div className="border-t border-hairline p-2">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-2">
            <Avatar name={user.name} color={user.color} size="sm" />
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs font-medium text-white">{user.name}</div>
              <div className="truncate text-[10px] text-slate-500">{user.email}</div>
            </div>
            <button
              onClick={signOut}
              title="退出登录"
              className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition-colors hover:bg-rose-500/10 hover:text-rose-300"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 pb-16 lg:pb-0 lg:pl-56">
        <header className="flex items-center gap-2.5 border-b border-hairline px-5 py-3 lg:hidden">
          <Logo size={22} />
          <span className="text-[13px] font-medium text-slate-200">{current?.label ?? "控制台"}</span>
          <button
            onClick={signOut}
            title="退出登录"
            className="ml-auto cursor-pointer rounded-lg p-1.5 text-slate-500 hover:text-rose-300"
          >
            <LogOut size={15} />
          </button>
        </header>

        <main className="mx-auto max-w-6xl p-5 md:p-8">
          <Outlet />
        </main>
      </div>

      <nav className="fixed inset-x-0 bottom-0 z-30 flex border-t border-hairline bg-surface py-1.5 lg:hidden">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              cn(
                "flex min-w-0 flex-1 flex-col items-center gap-1 rounded-lg px-1 py-1.5 text-[9.5px]",
                isActive ? "text-indigo-300" : "text-slate-500"
              )
            }
          >
            {item.icon}
            <span className="w-full truncate text-center">{item.label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  );
}
