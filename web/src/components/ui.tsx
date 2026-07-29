import { ReactNode } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X } from "lucide-react";
import { LOGO_URL, BRAND } from "../data/mock";
import { cn } from "../utils/cn";

/* ---------- Logo ---------- */
export function Logo({ size = 40, ring = false, className = "" }: { size?: number; ring?: boolean; className?: string }) {
  return (
    <div className={cn("relative shrink-0", className)} style={{ width: size, height: size }}>
      {ring && (
        <>
          <div className="orbit-ring absolute -inset-3 animate-[spin_16s_linear_infinite]" />
          <div className="orbit-ring absolute -inset-6 animate-[spin_26s_linear_infinite_reverse] opacity-60" />
        </>
      )}
      <img
        src={LOGO_URL}
        alt={BRAND.name}
        width={size}
        height={size}
        className="relative h-full w-full rounded-xl object-contain"
      />
    </div>
  );
}

export function BrandMark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-3">
      <Logo size={compact ? 30 : 38} />
      <div className="leading-tight">
        <div className={cn("font-semibold tracking-wide text-white", compact ? "text-sm" : "text-base")}>
          {BRAND.name}
        </div>
        {!compact && (
          <div className="text-[11px] tracking-[0.2em] text-slate-500">{BRAND.platform}</div>
        )}
      </div>
    </div>
  );
}

/* ---------- Avatar ---------- */
export function Avatar({ name, color, size = "md" }: { name: string; color: string; size?: "sm" | "md" | "lg" | "xl" }) {
  const s = { sm: "h-8 w-8 text-xs", md: "h-10 w-10 text-sm", lg: "h-14 w-14 text-lg", xl: "h-20 w-20 text-2xl" }[size];
  return (
    <div className={cn("flex shrink-0 items-center justify-center rounded-full bg-gradient-to-br font-semibold text-white", color, s)}>
      {name.slice(0, 1).toUpperCase()}
    </div>
  );
}

/* ---------- Buttons ---------- */
export function GlowButton({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "btn-glow inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg px-5 py-2.5 text-sm font-medium text-white",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function GhostButton({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "inline-flex cursor-pointer items-center justify-center gap-1.5 rounded-lg border border-hairline bg-transparent px-5 py-2.5 text-sm font-medium text-slate-300 transition-colors hover:border-slate-600 hover:bg-white/[0.04] hover:text-white disabled:cursor-not-allowed disabled:opacity-50",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

/** Small square button for row-level actions. Always pass a title — these are icon-only. */
export function IconButton({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn(
        "inline-flex h-8 w-8 cursor-pointer items-center justify-center rounded-lg text-slate-400 transition-colors hover:bg-white/[0.06] hover:text-white disabled:cursor-not-allowed disabled:opacity-40",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

/* ---------- Input ---------- */
export function Field({
  label, icon, hint, ...props
}: { label: string; icon?: ReactNode; hint?: ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-slate-400">{label}</span>
      <div className="field flex items-center gap-2.5 rounded-lg px-3 py-2.5">
        {icon && <span className="text-slate-500">{icon}</span>}
        <input
          className="w-full bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none disabled:cursor-not-allowed"
          {...props}
        />
      </div>
      {hint && <span className="mt-1.5 block text-[11px] leading-relaxed text-slate-500">{hint}</span>}
    </label>
  );
}

export function TextArea({
  label, hint, ...props
}: { label: string; hint?: ReactNode } & React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium text-slate-400">{label}</span>
      <div className="field rounded-lg px-3 py-2.5">
        <textarea
          className="w-full resize-y bg-transparent font-mono text-[13px] leading-relaxed text-white placeholder:text-slate-600 focus:outline-none"
          {...props}
        />
      </div>
      {hint && <span className="mt-1.5 block text-[11px] leading-relaxed text-slate-500">{hint}</span>}
    </label>
  );
}

/* ---------- Badge ---------- */
export function Badge({ children, tone = "slate" }: { children: ReactNode; tone?: "indigo" | "cyan" | "green" | "amber" | "red" | "slate" }) {
  const tones = {
    indigo: "border-indigo-500/25 bg-indigo-500/10 text-indigo-300",
    cyan: "border-cyan-500/25 bg-cyan-500/10 text-cyan-300",
    green: "border-emerald-500/25 bg-emerald-500/10 text-emerald-300",
    amber: "border-amber-500/25 bg-amber-500/10 text-amber-300",
    red: "border-rose-500/25 bg-rose-500/10 text-rose-300",
    slate: "border-slate-600/40 bg-slate-500/10 text-slate-400",
  };
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium", tones[tone])}>
      {children}
    </span>
  );
}

/* ---------- Page header ----------
   Every console page opens with this, so titles and actions line up across screens. */
export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold text-white">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm leading-relaxed text-slate-400">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ---------- Section panel ---------- */
export function Section({
  title, description, actions, children, className = "",
}: { title?: string; description?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("panel rounded-xl", className)}>
      {(title || actions) && (
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-hairline px-5 py-4">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold text-white">{title}</h2>}
            {description && <p className="mt-1 text-xs leading-relaxed text-slate-500">{description}</p>}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

/* ---------- Empty state ---------- */
export function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl bg-white/[0.04] text-slate-500">{icon}</div>
      <div className="text-sm font-medium text-slate-200">{title}</div>
      {description && <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-500">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

/* ---------- Inline message ---------- */
export function Notice({ tone = "info", children }: { tone?: "info" | "warn" | "error" | "success"; children: ReactNode }) {
  const tones = {
    info: "border-slate-600/40 bg-white/[0.03] text-slate-400",
    warn: "border-amber-500/25 bg-amber-500/[0.07] text-amber-200",
    error: "border-rose-500/25 bg-rose-500/[0.07] text-rose-200",
    success: "border-emerald-500/25 bg-emerald-500/[0.07] text-emerald-200",
  };
  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn("rounded-lg border px-3.5 py-3 text-xs leading-relaxed", tones[tone])}
    >
      {children}
    </div>
  );
}

/* ---------- Modal ---------- */
export function Modal({
  open, onClose, title, description, children, wide = false,
}: { open: boolean; onClose: () => void; title: string; description?: ReactNode; children: ReactNode; wide?: boolean }) {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/70 p-4 py-10 backdrop-blur-sm"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            role="dialog"
            aria-modal="true"
            className={cn("panel-raised my-auto w-full rounded-xl shadow-2xl shadow-black/50", wide ? "max-w-2xl" : "max-w-md")}
            initial={{ scale: 0.97, y: 12, opacity: 0 }}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.98, y: 8, opacity: 0 }}
            transition={{ duration: 0.16, ease: "easeOut" }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
              <div className="min-w-0">
                <h3 className="text-sm font-semibold text-white">{title}</h3>
                {description && <p className="mt-1 text-xs leading-relaxed text-slate-500">{description}</p>}
              </div>
              <IconButton onClick={onClose} title="关闭"><X size={16} /></IconButton>
            </div>
            <div className="p-5">{children}</div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/* ---------- Stat ---------- */
export function Stat({ label, value, sub, icon }: { label: string; value: string; sub?: string; icon?: ReactNode }) {
  return (
    <div className="panel rounded-xl p-4">
      <div className="flex items-center gap-2 text-xs text-slate-500">
        {icon && <span className="text-slate-600">{icon}</span>}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold tabular-nums text-white">{value}</div>
      {sub && <div className="mt-1 text-[11px] text-slate-500">{sub}</div>}
    </div>
  );
}

/* ---------- Page transition wrapper ---------- */
export function PageFade({ children }: { children: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}
