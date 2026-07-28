import { FormEvent, useEffect, useState } from "react";
import { Check, Info, Loader2, Mail, Save, ShieldAlert } from "lucide-react";
import { useOutletContext } from "react-router-dom";
import { AdminProfile, api, errorMessage } from "../api";
import { Badge, Field, GlowButton, PageFade } from "../components/ui";

export default function AdminSettings() {
  const admin = useOutletContext<AdminProfile>();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.adminRegistrationEmail().then((value) => {
      if (active) setEmail(value.registration_email_from ?? "");
    }).catch((value) => {
      if (active) setError(errorMessage(value));
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setSaved(false);
    setError(null);
    try {
      const value = await api.updateAdminRegistrationEmail(email.trim() || null);
      setEmail(value.registration_email_from ?? "");
      setSaved(true);
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  if (!admin.permissions.includes("manage_settings")) return <PageFade><div className="glass mx-auto max-w-2xl rounded-3xl p-8 text-center"><ShieldAlert size={34} className="mx-auto text-amber-300" /><h1 className="mt-4 text-xl font-bold text-white">没有设置权限</h1><p className="mt-2 text-sm text-slate-500">当前管理员角色不能修改系统设置。</p></div></PageFade>;

  return <PageFade><div className="mb-6 flex flex-wrap items-end justify-between gap-4"><div><div className="mb-2 flex items-center gap-2"><Badge tone="amber">Owner 设置</Badge><span className="text-xs text-slate-600">系统配置</span></div><h1 className="text-xl font-bold text-white">邮件设置</h1><p className="mt-1 text-sm text-slate-500">配置用户注册流程使用的发件人地址。</p></div></div><div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_300px]"><section className="glass rounded-3xl p-6 md:p-8"><div className="mb-6 flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-300"><Mail size={18} /></span><div><h2 className="text-sm font-semibold text-white">注册邮件发件地址</h2><p className="mt-1 text-xs leading-6 text-slate-500">该地址会保存到 PostgreSQL，应用不会从请求 Host 或前端状态推导它。</p></div></div>{loading ? <div className="flex items-center gap-2 py-8 text-sm text-slate-500"><Loader2 size={15} className="animate-spin" />正在读取设置</div> : <form className="space-y-5" onSubmit={submit}><Field label="发件邮箱" icon={<Mail size={15} />} type="email" autoComplete="email" placeholder="no-reply@example.com" value={email} onChange={(event) => setEmail(event.target.value)} /><div className="flex flex-wrap items-center justify-between gap-3 border-t border-white/6 pt-5"><div className="text-xs text-slate-600">留空可清除当前配置</div><GlowButton type="submit" disabled={busy}>{busy ? <Loader2 size={15} className="animate-spin" /> : saved ? <><Check size={14} className="mr-1 inline" />已保存</> : <><Save size={14} className="mr-1 inline" />保存设置</>}</GlowButton></div>{error && <div role="alert" className="rounded-xl border border-rose-400/20 bg-rose-500/10 px-3.5 py-3 text-xs text-rose-200">{error}</div>}</form>}</section><aside className="glass-soft rounded-3xl p-6"><Info size={18} className="text-indigo-300" /><h2 className="mt-4 text-sm font-semibold text-white">配置边界</h2><p className="mt-2 text-xs leading-6 text-slate-500">这里只保存发件人地址。SMTP 服务、发送凭据和邮件模板由后续邮件服务接入时单独配置。</p><div className="mt-5 rounded-xl border border-emerald-400/15 bg-emerald-500/5 px-3 py-2.5 text-xs leading-5 text-emerald-200/80">管理员写操作需要独立的 Session Cookie、CSRF Cookie 和请求头。</div></aside></div></PageFade>;
}
