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
      <div
        className="absolute -inset-1 rounded-full opacity-60 blur-md"
        style={{ background: "radial-gradient(circle, rgba(109,92,255,0.55), transparent 70%)" }}
      />
      <img
        src={LOGO_URL}
        alt={BRAND.name}
        width={size}
        height={size}
        className="relative h-full w-full rounded-xl object-contain drop-shadow-[0_0_12px_rgba(139,123,255,0.5)]"
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
          <div className="text-[11px] tracking-[0.2em] text-indigo-300/70">{BRAND.platform}</div>
        )}
      </div>
    </div>
  );
}

/* ---------- Avatar ---------- */
export function Avatar({ name, color, size = "md" }: { name: string; color: string; size?: "sm" | "md" | "lg" | "xl" }) {
  const s = { sm: "h-8 w-8 text-xs", md: "h-10 w-10 text-sm", lg: "h-14 w-14 text-lg", xl: "h-20 w-20 text-2xl" }[size];
  return (
    <div className={cn("flex shrink-0 items-center justify-center rounded-full bg-gradient-to-br font-semibold text-white shadow-lg", color, s)}>
      {name.slice(0, 1).toUpperCase()}
    </div>
  );
}

/* ---------- Buttons ---------- */
export function GlowButton({ children, className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      className={cn("btn-glow cursor-pointer rounded-xl px-6 py-2.5 text-sm font-semibold text-white", className)}
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
        "cursor-pointer rounded-xl border border-white/10 bg-white/[0.03] px-6 py-2.5 text-sm font-medium text-slate-300 transition-all hover:border-indigo-400/40 hover:bg-white/[0.07] hover:text-white",
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
  label, icon, ...props
}: { label: string; icon?: ReactNode } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-xs font-medium tracking-wide text-slate-400">{label}</span>
      <div className="field flex items-center gap-2.5 rounded-xl px-3.5 py-2.5">
        {icon && <span className="text-indigo-300/60">{icon}</span>}
        <input
          className="w-full bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none"
          {...props}
        />
      </div>
    </label>
  );
}

/* ---------- Badge ---------- */
export function Badge({ children, tone = "indigo" }: { children: ReactNode; tone?: "indigo" | "cyan" | "green" | "amber" | "red" | "slate" }) {
  const tones = {
    indigo: "border-indigo-400/30 bg-indigo-500/10 text-indigo-300",
    cyan: "border-cyan-400/30 bg-cyan-500/10 text-cyan-300",
    green: "border-emerald-400/30 bg-emerald-500/10 text-emerald-300",
    amber: "border-amber-400/30 bg-amber-500/10 text-amber-300",
    red: "border-rose-400/30 bg-rose-500/10 text-rose-300",
    slate: "border-slate-400/20 bg-slate-500/10 text-slate-400",
  };
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-medium", tones[tone])}>
      {children}
    </span>
  );
}

/* ---------- Modal ---------- */
export function Modal({
  open, onClose, title, children, wide = false,
}: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  return (
    <AnimatePresence>
      {open && (
        <motion.div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm"
          initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
          onClick={onClose}
        >
          <motion.div
            className={cn("glass w-full rounded-2xl p-6 shadow-2xl shadow-indigo-950/50", wide ? "max-w-2xl" : "max-w-md")}
            initial={{ scale: 0.92, y: 24, opacity: 0 }}
            animate={{ scale: 1, y: 0, opacity: 1 }}
            exit={{ scale: 0.95, y: 12, opacity: 0 }}
            transition={{ type: "spring", stiffness: 320, damping: 28 }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="mb-5 flex items-center justify-between">
              <h3 className="text-base font-semibold text-white">{title}</h3>
              <button onClick={onClose} className="cursor-pointer rounded-lg p-1.5 text-slate-500 transition hover:bg-white/5 hover:text-white">
                <X size={16} />
              </button>
            </div>
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

/* ---------- Stat card ---------- */
export function Stat({ label, value, sub, icon }: { label: string; value: string; sub?: string; icon: ReactNode }) {
  return (
    <div className="glass group relative overflow-hidden rounded-2xl p-5 transition-all hover:border-indigo-400/30">
      <div className="absolute -right-6 -top-6 h-24 w-24 rounded-full bg-indigo-500/10 blur-2xl transition-all group-hover:bg-indigo-500/20" />
      <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-500/15 text-indigo-300">
        {icon}
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
      <div className="mt-1 text-xs text-slate-500">{label}</div>
      {sub && <div className="mt-2 text-[11px] font-medium text-emerald-400">{sub}</div>}
    </div>
  );
}

/* ---------- Page transition wrapper ---------- */
export function PageFade({ children }: { children: ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      transition={{ duration: 0.35, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}
