import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AlertTriangle, Check, Loader2, Lock, X } from "lucide-react";
import { Avatar, GhostButton, GlowButton, Logo, Notice } from "../components/ui";
import { api, errorMessage, PendingAuthorization } from "../api";
import { SCOPE_MAP } from "../data/constants";
import { useStore } from "../store";

export default function OAuthConsent() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { user } = useStore();
  const requestId = params.get("request_id");
  const [pending, setPending] = useState<PendingAuthorization | null>(null);
  const [busy, setBusy] = useState<"approve" | "deny" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!requestId) {
      setError("缺少授权请求参数。");
      return;
    }
    if (!user) {
      navigate(`/login?request_id=${encodeURIComponent(requestId)}`, { replace: true });
      return;
    }
    void api.pendingAuthorization(requestId).then(setPending).catch((value) => setError(errorMessage(value)));
  }, [requestId, user, navigate]);

  const decide = async (decision: "approve" | "deny") => {
    if (!requestId) return;
    setBusy(decision);
    setError(null);
    try {
      const result = await api.decideAuthorization(requestId, decision);
      window.location.assign(result.redirect_to);
    } catch (value) {
      setError(errorMessage(value));
      setBusy(null);
    }
  };

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-app p-4">
      <div className="panel w-full max-w-[440px] overflow-hidden rounded-2xl">
        <div className="flex items-center gap-2.5 border-b border-hairline px-5 py-3.5">
          <Logo size={22} />
          <span className="text-[13px] text-slate-300">辰星通行证</span>
          <span className="ml-auto flex items-center gap-1.5 text-[11px] text-slate-500">
            <Lock size={11} /> 安全授权
          </span>
        </div>

        {!pending && !error && (
          <div className="flex items-center justify-center py-24">
            <Loader2 size={22} className="animate-spin text-slate-500" />
          </div>
        )}

        {error && !pending && (
          <div className="flex flex-col items-center px-6 py-16 text-center">
            <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-rose-500/10 text-rose-400">
              <AlertTriangle size={20} />
            </div>
            <h1 className="text-base font-semibold text-white">无法加载授权请求</h1>
            <p className="mt-2 max-w-sm text-xs leading-relaxed text-slate-500">{error}</p>
            <GhostButton className="mt-6" onClick={() => navigate("/console")}>返回控制台</GhostButton>
          </div>
        )}

        {pending && user && (
          <div className="px-6 py-7">
            <h1 className="text-lg font-semibold leading-snug text-white">
              {pending.client_name} 想要访问你的辰星通行证
            </h1>
            <p className="mt-2 text-xs leading-relaxed text-slate-500">
              授权后，该应用可以获取下列信息。你可以随时在通行证资料中撤销登录会话。
            </p>

            <div className="mt-5 flex items-center gap-2.5 rounded-lg border border-hairline px-3 py-2.5">
              <Avatar name={user.name} color={user.color} size="sm" />
              <div className="min-w-0">
                <div className="truncate text-[13px] text-slate-200">{user.name}</div>
                <div className="truncate text-[11px] text-slate-500">{user.email}</div>
              </div>
            </div>

            <div className="mt-5">
              <div className="mb-2 text-xs font-medium text-slate-400">将获得的权限</div>
              <ul className="space-y-2.5">
                {pending.scopes.map((scope) => {
                  const known = SCOPE_MAP.get(scope);
                  return (
                    <li key={scope} className="flex items-start gap-2.5">
                      <span
                        className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full ${
                          known ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400"
                        }`}
                      >
                        {known ? <Check size={10} /> : <AlertTriangle size={9} />}
                      </span>
                      <span className="min-w-0 text-[13px] leading-snug text-slate-300">
                        {known?.consent ?? "该应用声明的访问范围"}
                        <code className="ml-1.5 font-mono text-[11px] text-slate-500">{scope}</code>
                      </span>
                    </li>
                  );
                })}
              </ul>
            </div>

            <div className="mt-5 rounded-lg border border-hairline bg-white/[0.02] px-3 py-2.5 text-[11px] leading-relaxed text-slate-500">
              授权后将跳转至 <span className="font-mono text-slate-400">{pending.redirect_host}</span>
              。请确认这是你信任的站点。
            </div>

            {error && <div className="mt-4"><Notice tone="error">{error}</Notice></div>}

            <div className="mt-6 grid grid-cols-2 gap-2.5">
              <GhostButton disabled={busy !== null} onClick={() => void decide("deny")}>
                {busy === "deny" ? <Loader2 size={15} className="animate-spin" /> : <X size={15} />} 拒绝
              </GhostButton>
              <GlowButton disabled={busy !== null} onClick={() => void decide("approve")}>
                {busy === "approve" ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />} 允许
              </GlowButton>
            </div>
          </div>
        )}
      </div>

      <p className="mt-4 text-[11px] text-slate-600">授权请求会在短时间后失效</p>
    </div>
  );
}
