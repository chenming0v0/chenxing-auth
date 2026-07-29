import { FormEvent, useState } from "react";
import { ArrowRight, KeyRound, Loader2, ShieldCheck, UserRound } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { errorMessage, api } from "../api";
import { AuthShell, FormError } from "./Auth";
import { Field, GlowButton } from "../components/ui";

export default function AdminLogin() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.adminLogin({ username, password });
      navigate("/admin-console/settings", { replace: true });
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="管理员登录" subtitle="进入辰星认证中枢管理控制台">
      <form className="mt-6 space-y-4" onSubmit={submit}>
        <FormError value={error} />
        <Field label="管理员用户名" icon={<UserRound size={15} />} autoComplete="username" required minLength={3} value={username} onChange={(event) => setUsername(event.target.value)} placeholder="chenxing-admin" />
        <Field label="密码" icon={<KeyRound size={15} />} type="password" autoComplete="current-password" required minLength={10} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="至少 10 个字符" />
        <GlowButton className="w-full py-3" type="submit" disabled={busy}>{busy ? <Loader2 size={16} className="mx-auto animate-spin" /> : <>登录管理后台 <ArrowRight size={15} className="ml-1 inline" /></>}</GlowButton>
      </form>
      <div className="mt-6 flex items-center justify-center gap-2 text-xs text-slate-600"><ShieldCheck size={13} className="text-indigo-300/70" />管理员 Session 使用独立 Cookie 与 CSRF 校验</div>
      <p className="mt-4 text-center text-xs text-slate-500"><Link to="/" className="text-indigo-400 hover:text-indigo-300">返回辰星通行证</Link></p>
    </AuthShell>
  );
}
