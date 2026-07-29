import { useState } from "react";
import { Check, Copy, Eye, EyeOff } from "lucide-react";
import { IconButton } from "./ui";
import { cn } from "../utils/cn";

function useCopy() {
  const [copied, setCopied] = useState(false);
  const copy = (value: string) => {
    void navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };
  return { copied, copy };
}

/**
 * A labelled, copyable value. `secret` masks the value behind a reveal toggle —
 * use it for anything the server only returns once.
 */
export function CopyField({
  label, value, secret = false, hint, className = "",
}: { label: string; value: string; secret?: boolean; hint?: string; className?: string }) {
  const [revealed, setRevealed] = useState(false);
  const { copied, copy } = useCopy();
  const hidden = secret && !revealed;

  return (
    <div className={className}>
      <div className="mb-1.5 flex items-baseline gap-2">
        <span className="text-xs font-medium text-slate-400">{label}</span>
        {hint && <span className="text-[11px] text-slate-600">{hint}</span>}
      </div>
      <div className="code-block flex items-center gap-2 rounded-lg py-2 pl-3 pr-2">
        <span className={cn("min-w-0 flex-1 truncate text-[13px]", hidden ? "text-slate-500" : "text-slate-200")}>
          {hidden ? "•".repeat(Math.min(40, Math.max(16, value.length))) : value}
        </span>
        {secret && (
          <IconButton title={revealed ? "隐藏" : "显示"} onClick={() => setRevealed((v) => !v)}>
            {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
          </IconButton>
        )}
        <IconButton title={copied ? "已复制" : "复制"} onClick={() => copy(value)}>
          {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
        </IconButton>
      </div>
    </div>
  );
}

/** Read-only endpoint URL row, for the discovery/endpoint reference table. */
export function EndpointRow({ label, method, url }: { label: string; method?: string; url: string }) {
  const { copied, copy } = useCopy();
  return (
    <div className="flex items-center gap-2 border-b border-hairline px-4 py-2.5 last:border-b-0">
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="truncate text-xs text-slate-400">{label}</span>
          {method && <span className="font-mono text-[10px] font-medium text-emerald-400">{method}</span>}
        </div>
        <code className="mt-0.5 block truncate font-mono text-[12px] text-slate-300">{url}</code>
      </div>
      <IconButton title={copied ? "已复制" : "复制"} onClick={() => copy(url)}>
        {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
      </IconButton>
    </div>
  );
}

/** Fenced code sample with a copy affordance. */
export function CodeSample({ code, language }: { code: string; language?: string }) {
  const { copied, copy } = useCopy();
  return (
    <div className="code-block relative rounded-lg">
      <div className="absolute right-2 top-2 flex items-center gap-2">
        {language && <span className="text-[10px] uppercase tracking-wider text-slate-600">{language}</span>}
        <IconButton title={copied ? "已复制" : "复制"} onClick={() => copy(code)}>
          {copied ? <Check size={13} className="text-emerald-400" /> : <Copy size={13} />}
        </IconButton>
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all p-4 pr-16 text-[12.5px] leading-relaxed text-slate-300">{code}</pre>
    </div>
  );
}
