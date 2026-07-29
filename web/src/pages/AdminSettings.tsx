import { FormEvent, useEffect, useState } from "react";
import { Check, Loader2, Mail, Save, ShieldAlert } from "lucide-react";
import { useOutletContext } from "react-router-dom";
import { AdminProfile, api, errorMessage } from "../api";
import { Field, GlowButton, Notice, PageFade, PageHeader, Section } from "../components/ui";

export default function AdminSettings() {
  const admin = useOutletContext<AdminProfile>();
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void api.adminRegistrationEmail()
      .then((value) => { if (active) setEmail(value.registration_email_from ?? ""); })
      .catch((value) => { if (active) setError(errorMessage(value)); })
      .finally(() => { if (active) setLoading(false); });
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

  if (!admin.permissions.includes("manage_settings")) {
    return (
      <PageFade>
        <div className="panel mx-auto max-w-lg rounded-xl px-6 py-14 text-center">
          <ShieldAlert size={24} className="mx-auto text-amber-400" />
          <h1 className="mt-4 text-base font-semibold text-white">没有设置权限</h1>
          <p className="mt-2 text-xs text-slate-500">当前角色不能修改系统设置。</p>
        </div>
      </PageFade>
    );
  }

  return (
    <PageFade>
      <PageHeader title="邮件设置" description="配置注册流程使用的发件人地址。" />

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_280px]">
        <Section
          title="注册邮件发件地址"
          description="保存在 PostgreSQL 中，不会从请求 Host 或前端状态推导。"
        >
          {loading ? (
            <div className="flex items-center gap-2 py-6 text-sm text-slate-500">
              <Loader2 size={15} className="animate-spin" /> 正在读取设置…
            </div>
          ) : (
            <form className="space-y-4" onSubmit={submit}>
              <Field
                label="发件邮箱"
                icon={<Mail size={15} />}
                type="email"
                autoComplete="email"
                placeholder="no-reply@example.com"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                hint="留空可清除当前配置。"
              />
              {error && <Notice tone="error">{error}</Notice>}
              <div className="flex justify-end border-t border-hairline pt-4">
                <GlowButton type="submit" disabled={busy}>
                  {busy ? <Loader2 size={15} className="animate-spin" /> : saved ? <Check size={14} /> : <Save size={14} />}
                  {saved ? "已保存" : "保存设置"}
                </GlowButton>
              </div>
            </form>
          )}
        </Section>

        <Section title="配置边界">
          <p className="text-xs leading-relaxed text-slate-400">
            这里只保存发件人地址。SMTP 服务、发送凭据和邮件模板会在邮件服务接入时单独配置。
          </p>
        </Section>
      </div>
    </PageFade>
  );
}
