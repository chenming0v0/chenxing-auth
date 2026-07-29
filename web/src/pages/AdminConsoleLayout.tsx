import { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import { LogOut, Mail, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, AdminProfile, ApiError, errorMessage } from "../api";
import { Badge, GlowButton, Logo } from "../components/ui";
import { BRAND } from "../data/mock";
import { cn } from "../utils/cn";

const NAV = [{ to: "/admin-console/settings", label: "邮件设置", icon: <Mail size={16} /> }];

export default function AdminConsoleLayout() {
  const navigate = useNavigate();
  const [admin, setAdmin] = useState<AdminProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.adminMe()
      .then((profile) => { if (active) setAdmin(profile); })
      .catch((value) => {
        if (!active) return;
        if (value instanceof ApiError && value.status === 401) {
          navigate("/login?return_to=%2Fadmin-console", { replace: true });
        } else if (value instanceof ApiError && value.status === 403) {
          navigate("/console", { replace: true });
        } else {
          setError(errorMessage(value));
        }
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [navigate]);

  const logout = async () => {
    try { await api.logout(); } finally { navigate("/", { replace: true }); }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-app text-sm text-slate-500">
        正在验证管理员身份…
      </div>
    );
  }

  if (!admin) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-app p-6">
        <div className="panel max-w-md rounded-xl px-6 py-12 text-center">
          <ShieldAlert size={24} className="mx-auto text-amber-400" />
          <h1 className="mt-4 text-base font-semibold text-white">无法加载管理权限</h1>
          <p className="mt-2 text-xs leading-relaxed text-slate-500">{error ?? "请使用管理员身份登录。"}</p>
          <Link to="/login?return_to=%2Fadmin-console" className="mt-6 inline-block">
            <GlowButton>返回登录</GlowButton>
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-app">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-56 flex-col border-r border-hairline bg-surface lg:flex">
        <Link to="/admin-console/settings" className="flex items-center gap-2.5 px-4 py-4">
          <Logo size={26} />
          <span className="leading-tight">
            <span className="block text-[13px] font-semibold text-white">{BRAND.name}</span>
            <span className="block text-[10px] text-slate-500">管理控制台</span>
          </span>
        </Link>

        <div className="mx-2 mb-1 flex items-center gap-1.5 rounded-lg border border-amber-500/20 bg-amber-500/[0.06] px-2.5 py-2 text-[11px] text-amber-200/90">
          <ShieldCheck size={12} /> 管理员模式
        </div>

        <nav className="flex-1 px-2 py-2">
          <div className="mb-1 mt-2 px-2.5 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
            系统管理
          </div>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
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
          ))}
        </nav>

        <div className="border-t border-hairline p-2">
          <div className="flex items-center gap-2.5 rounded-lg px-2 py-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-amber-400 to-orange-600 text-xs font-semibold text-white">
              {(admin.username ?? "A").slice(0, 1).toUpperCase()}
            </div>
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-xs font-medium text-white">{admin.username ?? "管理员"}</div>
              <div className="truncate text-[10px] text-slate-500">{admin.role}</div>
            </div>
            <button
              onClick={() => void logout()}
              title="退出管理后台"
              className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition-colors hover:bg-rose-500/10 hover:text-rose-300"
            >
              <LogOut size={15} />
            </button>
          </div>
        </div>
      </aside>

      <div className="flex-1 lg:pl-56">
        <header className="flex items-center gap-2.5 border-b border-hairline px-5 py-3">
          <Logo size={20} className="lg:hidden" />
          <span className="text-xs text-slate-400">管理控制台</span>
          <Badge tone="amber">{admin.role}</Badge>
          <button
            onClick={() => void logout()}
            title="退出管理后台"
            className="ml-auto cursor-pointer rounded-lg p-1.5 text-slate-500 hover:text-rose-300 lg:hidden"
          >
            <LogOut size={15} />
          </button>
        </header>

        <main className="mx-auto max-w-5xl p-5 md:p-8">
          <Outlet context={admin} />
        </main>
      </div>
    </div>
  );
}
