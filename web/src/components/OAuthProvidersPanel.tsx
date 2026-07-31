import { FormEvent, useEffect, useState } from "react";
import { Loader2, Pencil, Plus, Save, X } from "lucide-react";
import { api, ClientAuthMethod, OAuthProvider, ProviderInput, errorMessage } from "../api";
import { Badge, Field, GhostButton, GlowButton, Notice, Section } from "./ui";

const EMPTY_FORM: ProviderInput = {
  name: "", slug: "", authorization_endpoint: "", token_endpoint: "", userinfo_endpoint: "",
  client_id: "", client_secret: null, scopes: ["openid", "profile", "email"],
  subject_claim: "sub", email_claim: "email", name_claim: null, email_verified_claim: null,
  client_auth_method: "basic",
};

export default function OAuthProvidersPanel() {
  const [providers, setProviders] = useState<OAuthProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [editingSlug, setEditingSlug] = useState<string | null>(null);
  const [form, setForm] = useState<ProviderInput>(EMPTY_FORM);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      setProviders(await api.adminProviders());
      setError(null);
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void load(); }, []);

  const resetForm = () => { setForm(EMPTY_FORM); setEditingSlug(null); };

  const startEdit = (provider: OAuthProvider) => {
    setForm({
      name: provider.name, slug: provider.slug,
      authorization_endpoint: provider.authorization_endpoint,
      token_endpoint: provider.token_endpoint,
      userinfo_endpoint: provider.userinfo_endpoint,
      client_id: provider.client_id, client_secret: null, scopes: provider.scopes,
      subject_claim: provider.subject_claim, email_claim: provider.email_claim,
      name_claim: provider.name_claim, email_verified_claim: provider.email_verified_claim,
      client_auth_method: provider.client_auth_method,
    });
    setEditingSlug(provider.slug);
  };

  const setField = <K extends keyof ProviderInput>(key: K, value: ProviderInput[K]) => {
    setForm((previous) => ({ ...previous, [key]: value }));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setResult(null);
    setError(null);
    try {
      if (editingSlug) {
        await api.updateAdminProvider(editingSlug, form);
        setResult("提供商已更新。");
      } else {
        await api.createAdminProvider(form);
        setResult("提供商已创建。");
      }
      resetForm();
      await load();
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const toggleStatus = async (provider: OAuthProvider) => {
    try {
      await api.setAdminProviderStatus(provider.slug, provider.status === "active" ? "disable" : "enable");
      await load();
    } catch (value) {
      setError(errorMessage(value));
    }
  };

  return (
    <Section
      title="OAuth 提供商"
      description="配置符合 OAuth 2.0 授权码流程和 UserInfo JSON 接口的外部身份提供商。"
      actions={
        <GhostButton type="button" onClick={resetForm}>
          <Plus size={14} /> 新建提供商
        </GhostButton>
      }
    >
      {loading ? (
        <div className="flex items-center gap-2 py-6 text-sm text-slate-500">
          <Loader2 size={15} className="animate-spin" /> 正在加载提供商…
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-hairline text-[11px] uppercase tracking-wider text-slate-600">
                <th className="px-4 py-3">名称</th>
                <th className="px-4 py-3">回调 URL</th>
                <th className="px-4 py-3">状态</th>
                <th className="px-4 py-3">Secret</th>
                <th className="px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {providers.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-600">暂无自定义 OAuth 提供商</td></tr>
              ) : providers.map((provider) => (
                <tr key={provider.slug} className="border-b border-hairline/60 hover:bg-white/[0.02]">
                  <td className="px-4 py-3">
                    <div className="font-medium text-white">{provider.name}</div>
                    <div className="text-xs text-slate-500">{provider.slug}</div>
                  </td>
                  <td className="max-w-[260px] truncate px-4 py-3 font-mono text-xs text-slate-400" title={provider.callback_uri}>{provider.callback_uri}</td>
                  <td className="px-4 py-3">
                    <Badge tone={provider.status === "active" ? "green" : "red"}>
                      {provider.status === "active" ? "已启用" : "已停用"}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">{provider.client_secret_configured ? "已配置" : "未配置"}</td>
                  <td className="px-4 py-3 text-right">
                    <button type="button" onClick={() => startEdit(provider)} className="mr-1 rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white" title="编辑"><Pencil size={14} /></button>
                    <button type="button" onClick={() => void toggleStatus(provider)} className="rounded-lg p-2 text-xs text-slate-500 hover:bg-white/5 hover:text-white" title={provider.status === "active" ? "停用" : "启用"}>{provider.status === "active" ? "停用" : "启用"}</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <form onSubmit={submit} className="mt-6 grid gap-4 border-t border-hairline pt-5 lg:grid-cols-2">
        <h3 className="text-sm font-semibold text-white lg:col-span-2">{editingSlug ? "编辑提供商" : "添加提供商"}</h3>
        <Field label="名称" required maxLength={128} value={form.name} onChange={(event) => setField("name", event.target.value)} />
        <Field label="Slug" required pattern="[a-z0-9_-]+" maxLength={64} readOnly={!!editingSlug} value={form.slug} onChange={(event) => setField("slug", event.target.value)} hint={editingSlug ? "Slug 创建后不可修改。" : undefined} />
        <Field label="授权地址" required type="url" value={form.authorization_endpoint} onChange={(event) => setField("authorization_endpoint", event.target.value)} />
        <Field label="Token 地址" required type="url" value={form.token_endpoint} onChange={(event) => setField("token_endpoint", event.target.value)} />
        <Field label="UserInfo 地址" required type="url" value={form.userinfo_endpoint} onChange={(event) => setField("userinfo_endpoint", event.target.value)} />
        <Field label="Client ID" required maxLength={512} value={form.client_id} onChange={(event) => setField("client_id", event.target.value)} />
        <Field label="Client Secret" type="password" autoComplete="new-password" value={form.client_secret ?? ""} onChange={(event) => setField("client_secret", event.target.value || null)} hint={editingSlug ? "编辑时留空以保留现有 Secret。" : "创建时必填。"} />
        <Field label="Scopes" required value={form.scopes.join(" ")} onChange={(event) => setField("scopes", event.target.value.trim() ? event.target.value.trim().split(/\s+/) : [])} hint="以空格分隔。" />
        <Field label="Subject Claim" required value={form.subject_claim} onChange={(event) => setField("subject_claim", event.target.value)} />
        <Field label="Email Claim" required value={form.email_claim} onChange={(event) => setField("email_claim", event.target.value)} />
        <Field label="Name Claim" value={form.name_claim ?? ""} onChange={(event) => setField("name_claim", event.target.value || null)} />
        <Field label="Email Verified Claim" value={form.email_verified_claim ?? ""} onChange={(event) => setField("email_verified_claim", event.target.value || null)} />
        <label className="block">
          <span className="mb-1.5 block text-xs font-medium text-slate-400">Client 认证</span>
          <div className="field flex items-center gap-2.5 rounded-lg px-3 py-2.5">
            <select className="w-full bg-transparent text-sm text-white focus:outline-none" value={form.client_auth_method} onChange={(event) => setField("client_auth_method", event.target.value as ClientAuthMethod)}>
              <option value="basic">HTTP Basic</option>
              <option value="request_body">Request Body</option>
            </select>
          </div>
        </label>

        {error && <div className="lg:col-span-2"><Notice tone="error">{error}</Notice></div>}
        {result && <div className="lg:col-span-2"><Notice tone="success">{result}</Notice></div>}

        <div className="flex items-center gap-3 border-t border-hairline pt-4 lg:col-span-2">
          <GlowButton type="submit" disabled={busy}>
            {busy ? <Loader2 size={15} className="animate-spin" /> : <Save size={14} />}
            保存提供商
          </GlowButton>
          {editingSlug && (
            <GhostButton type="button" onClick={resetForm}>
              <X size={14} /> 取消编辑
            </GhostButton>
          )}
        </div>
      </form>
    </Section>
  );
}
