import { FormEvent, useState } from "react";
import { ArrowRight, CheckCircle2, KeyRound, Loader2, LockKeyhole, Mail, UserRound } from "lucide-react";
import { ApiError, api, errorMessage } from "../api";
import { Field, GlowButton } from "../components/ui";
import { AuthShell, FormError } from "./Auth";

export default function Bootstrap({ onComplete }: { onComplete: () => void }) {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== confirmation) {
      setError("两次输入的密码不一致");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.bootstrapAdmin({ username, email, password });
      setSuccess(true);
      window.setTimeout(onComplete, 1300);
    } catch (value) {
      if (value instanceof ApiError && value.code === "bootstrap_already_completed") {
        onComplete();
        return;
      }
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return <AuthShell title="初始化认证中枢" subtitle="设置第一个管理员账户，开始管理辰星身份服务">
    {success ? <div className="mt-8 rounded-2xl border border-emerald-400/20 bg-emerald-500/10 p-5 text-center" role="status">
      <CheckCircle2 className="mx-auto text-emerald-300" size={30} />
      <div className="mt-3 text-sm font-semibold text-emerald-100">初始化成功</div>
      <div className="mt-1 text-xs text-emerald-200/70">即将跳转到通行证登录页</div>
    </div> : <form className="mt-6 space-y-4" onSubmit={submit}>
      <FormError value={error} />
      <Field label="Owner 用户名" icon={<UserRound size={15} />} type="text" autoComplete="username" required minLength={3} maxLength={64} placeholder="chenxing-owner" value={username} onChange={(event) => setUsername(event.target.value)} />
      <Field label="邮箱" icon={<Mail size={15} />} type="email" autoComplete="email" required placeholder="owner@example.com" value={email} onChange={(event) => setEmail(event.target.value)} />
      <Field label="密码" icon={<LockKeyhole size={15} />} type="password" autoComplete="new-password" required minLength={10} placeholder="至少 10 个字符" value={password} onChange={(event) => setPassword(event.target.value)} />
      <Field label="确认密码" icon={<KeyRound size={15} />} type="password" autoComplete="new-password" required minLength={10} placeholder="再次输入密码" value={confirmation} onChange={(event) => setConfirmation(event.target.value)} />
      <div className="rounded-xl border border-indigo-400/10 bg-indigo-500/5 px-3.5 py-3 text-xs leading-relaxed text-slate-500">这个账户会获得认证中枢的 Owner 权限。初始化完成后，其他管理员只能由已登录管理员创建。</div>
      <GlowButton className="w-full py-3" type="submit" disabled={busy}>{busy ? <Loader2 size={16} className="mx-auto animate-spin" /> : <>完成初始化 <ArrowRight size={15} className="ml-1 inline" /></>}</GlowButton>
    </form>}
  </AuthShell>;
}
