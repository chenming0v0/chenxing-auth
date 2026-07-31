import { ReactNode } from "react";
import { Crown, Gauge, KeyRound, Zap, CalendarClock } from "lucide-react";
import { Badge, PageFade, PageHeader } from "../../components/ui";
import { cn } from "../../utils/cn";

/* ---------- 套餐 / 权益数据 ----------
   TODO: 后端 `GET /api/v1/auth/entitlements` 就绪后，改为从 store / api 拉取，
   并把 PREVIEW 常量删除。契约见 docs/plan-entitlements-frontend.md。
   这里只展示本产品真实存在的四项资源，不编造邮箱/域名/存储等概念。 */
interface Entitlement {
  key: string;
  label: string;
  icon: ReactNode;
  used: number;
  /** 数字 = 上限；null = 无限（∞）；undefined = 只是个数值、无上限概念（如 QPS）。 */
  limit?: number | null;
}

interface PlanInfo {
  code: string;
  name: string;
  description?: string;
  /** "permanent" 或 RFC3339 到期时间字符串。 */
  validity: string;
}

const PREVIEW_PLAN: PlanInfo = {
  code: "basic",
  name: "基础版",
  description: "默认套餐",
  validity: "permanent",
};

const PREVIEW_ENTITLEMENTS: Entitlement[] = [
  { key: "oauth_clients", label: "OAuth 应用数", icon: <KeyRound size={15} />, used: 1, limit: 2 },
  { key: "daily_auth", label: "每日授权调用", icon: <Zap size={15} />, used: 0, limit: 2_500 },
  { key: "monthly_auth", label: "每月授权调用", icon: <Zap size={15} />, used: 2_300, limit: 50_000 },
  { key: "max_qps", label: "最大并发（请求/秒）", icon: <Gauge size={15} />, used: 35 },
];

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
        <span className="text-slate-600">{item.icon}</span>
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
  const plan = PREVIEW_PLAN;
  const entitlements = PREVIEW_ENTITLEMENTS;

  return (
    <PageFade>
      <PageHeader
        title="当前套餐与权益"
        description="查看你的套餐等级，以及各项资源的用量、上限与剩余额度。"
      />

      {/* 套餐 hero —— 全站仅 hero 面允许使用渐变。 */}
      <div className="relative mb-6 overflow-hidden rounded-2xl border border-hairline p-6 md:p-7">
        <div className="absolute inset-0 bg-gradient-to-br from-indigo-600 via-indigo-500 to-blue-600" />
        <div className="absolute -right-16 -top-20 h-72 w-72 rounded-full bg-white/15 blur-3xl" />
        <div className="absolute -bottom-24 right-24 h-64 w-64 rounded-full bg-cyan-300/20 blur-3xl" />

        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-[0.22em] text-white/70">
              {plan.code}
            </div>
            <div className="mt-1 flex items-center gap-2.5">
              <Crown size={26} className="text-amber-300" />
              <span className="text-3xl font-bold tracking-tight text-white">{plan.name}</span>
            </div>
            {plan.description && <div className="mt-4 text-sm text-white/80">{plan.description}</div>}
          </div>

          <div className="flex flex-col items-end gap-2">
            <span className="inline-flex items-center gap-1.5 rounded-lg bg-white/15 px-3 py-1.5 text-xs font-medium text-white backdrop-blur-sm">
              <Crown size={14} /> 当前套餐
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-lg bg-white/15 px-3 py-1.5 text-xs font-medium text-white backdrop-blur-sm">
              <CalendarClock size={14} /> {validityLabel(plan.validity)}
            </span>
          </div>
        </div>
      </div>

      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-white">资源权益</h2>
        <Badge tone="indigo">{entitlements.length} 项</Badge>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {entitlements.map((item) => (
          <EntitlementCard key={item.key} item={item} />
        ))}
      </div>
    </PageFade>
  );
}
