import { ReactNode, useEffect, useState } from "react";
import { Crown, Gauge, KeyRound, Zap, CalendarClock } from "lucide-react";
import { Badge, Notice, PageFade, PageHeader } from "../../components/ui";
import { api, EntitlementsResponse, Entitlement, errorMessage } from "../../api";
import { cn } from "../../utils/cn";

/* 权益项的图标按 key 映射（后端只返回 key/label/used/limit），
   未知 key 回退到一个通用图标，后端新增权益项时前端不会崩。 */
const ICON_BY_KEY: Record<string, ReactNode> = {
  oauth_clients: <KeyRound size={15} />,
  daily_auth: <Zap size={15} />,
  monthly_auth: <Zap size={15} />,
  max_qps: <Gauge size={15} />,
};

function iconFor(key: string): ReactNode {
  return ICON_BY_KEY[key] ?? <Gauge size={15} />;
}

function formatNumber(value: number): string {
  return value.toLocaleString("zh-CN");
}

function validityLabel(validity: string): string {
  if (validity === "permanent") return "永久有效";
  const date = new Date(validity);
  if (Number.isNaN(date.getTime())) return validity;
  return `有效至 ${date.toLocaleDateString("zh-CN")}`;
}

function EntitlementCard({ item }: { item: Entitlement }) {
  const hasLimit = typeof item.limit === "number";
  const unlimited = item.limit === null;
  const remaining = hasLimit ? Math.max(0, (item.limit as number) - item.used) : null;
  const pct = hasLimit && (item.limit as number) > 0
    ? Math.min(100, Math.round((item.used / (item.limit as number)) * 100))
    : 0;

  return (
    <div className="panel rounded-xl p-4 transition-colors hover:border-slate-600">
      <div className="flex items-center gap-2 text-xs font-medium text-slate-400">
        <span className="text-slate-600">{iconFor(item.key)}</span>
        {item.label}
      </div>

      <div className="mt-3 flex items-baseline gap-1.5">
        <span className="text-2xl font-semibold tabular-nums text-white">{formatNumber(item.used)}</span>
        {hasLimit && <span className="text-sm text-slate-500">/ {formatNumber(item.limit as number)}</span>}
        {unlimited && <span className="text-sm text-slate-500">/ ∞</span>}
      </div>

      {hasLimit ? (
        <>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/[0.06]">
            <div
              className={cn(
                "h-full rounded-full transition-[width] duration-500",
                pct >= 90 ? "bg-rose-500" : pct >= 70 ? "bg-amber-500" : "bg-accent-soft"
              )}
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="mt-2 text-[11px] text-slate-500">剩余 {formatNumber(remaining as number)}</div>
        </>
      ) : (
        <div className="mt-3 h-1.5 rounded-full bg-white/[0.03]" />
      )}
    </div>
  );
}

export default function Entitlements() {
  const [data, setData] = useState<EntitlementsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api.entitlements()
      .then((response) => { if (active) { setData(response); setError(null); } })
      .catch((value) => { if (active) setError(errorMessage(value)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  return (
    <PageFade>
      <PageHeader
        title="当前套餐与权益"
        description="查看你的套餐等级，以及各项资源的用量、上限与剩余额度。"
      />

      {loading && <div className="py-16 text-center text-sm text-slate-500">正在加载套餐信息…</div>}

      {!loading && error && <Notice tone="error">{error}</Notice>}

      {!loading && !error && data && (
        <>
          {/* 套餐 hero —— 全站仅 hero 面允许使用渐变。 */}
          <div className="relative mb-6 overflow-hidden rounded-2xl border border-hairline p-6 md:p-7">
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-600 via-indigo-500 to-blue-600" />
            <div className="absolute -right-16 -top-20 h-72 w-72 rounded-full bg-white/15 blur-3xl" />
            <div className="absolute -bottom-24 right-24 h-64 w-64 rounded-full bg-cyan-300/20 blur-3xl" />

            <div className="relative flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/70">
                  {data.plan.code}
                </div>
                <div className="mt-1 flex items-center gap-2.5">
                  <Crown size={26} className="text-amber-300" />
                  <span className="text-3xl font-bold tracking-tight text-white">{data.plan.name}</span>
                </div>
                {data.plan.description && (
                  <div className="mt-4 text-sm text-white/80">{data.plan.description}</div>
                )}
              </div>

              <div className="flex flex-col items-end gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-lg bg-white/15 px-3 py-1.5 text-xs font-medium text-white backdrop-blur-sm">
                  <Crown size={14} /> 当前套餐
                </span>
                <span className="inline-flex items-center gap-1.5 rounded-lg bg-white/15 px-3 py-1.5 text-xs font-medium text-white backdrop-blur-sm">
                  <CalendarClock size={14} /> {validityLabel(data.plan.validity)}
                </span>
              </div>
            </div>
          </div>

          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">资源权益</h2>
            <Badge tone="indigo">{data.entitlements.length} 项</Badge>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {data.entitlements.map((item) => (
              <EntitlementCard key={item.key} item={item} />
            ))}
          </div>
        </>
      )}
    </PageFade>
  );
}
