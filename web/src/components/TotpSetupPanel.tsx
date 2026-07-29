import { useState } from "react";
import { Check, Copy } from "lucide-react";
import { QRCodeSVG } from "qrcode.react";
import { TotpSetupResponse } from "../api";

async function copyText(value: string) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }

  const textarea = document.createElement("textarea");
  textarea.value = value;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.appendChild(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) throw new Error("copy failed");
}

export function TotpSetupPanel({ setup }: { setup: TotpSetupResponse }) {
  const [copied, setCopied] = useState(false);

  const copySecret = async () => {
    try {
      await copyText(setup.secret_base32);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-slate-600/40 bg-white/[0.03] p-3.5 text-xs leading-relaxed text-slate-400">
        <p>请使用验证器扫描二维码，然后输入当前六位验证码。</p>
        <div className="mt-4 flex justify-center rounded-lg bg-white p-4">
          <QRCodeSVG
            value={setup.otpauth_url}
            size={192}
            level="M"
            includeMargin
            className="h-auto w-full max-w-[192px]"
            aria-label="TOTP 验证器绑定二维码"
          />
        </div>
        <p className="mt-3 text-center text-[11px] text-slate-500">
          支持 Google Authenticator、Microsoft Authenticator 和 2FAS
        </p>
      </div>

      <details className="rounded-lg border border-slate-600/40 bg-white/[0.02] px-3.5 py-3">
        <summary className="cursor-pointer text-xs font-medium text-indigo-300">
          无法扫描？手动输入密钥
        </summary>
        <div className="mt-3 flex items-center gap-2">
          <code className="min-w-0 flex-1 break-all rounded-md border border-slate-700/70 bg-black/20 px-2.5 py-2 font-mono text-[11px] leading-relaxed text-cyan-300">
            {setup.secret_base32}
          </code>
          <button
            type="button"
            title={copied ? "已复制密钥" : "复制密钥"}
            aria-label={copied ? "已复制密钥" : "复制密钥"}
            className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-slate-700/70 text-slate-400 transition-colors hover:border-indigo-400/60 hover:text-white"
            onClick={copySecret}
          >
            {copied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        </div>
      </details>
    </div>
  );
}
