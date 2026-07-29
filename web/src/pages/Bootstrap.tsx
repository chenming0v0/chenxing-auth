import { FormEvent, useState } from "react";
import { ArrowRight, CheckCircle2, KeyRound, Loader2, LockKeyhole, Mail, UserRound } from "lucide-react";
import { ApiError, api, errorMessage } from "../api";
import { Field, GlowButton, Notice } from "../components/ui";
import { AuthShell } from "./Auth";

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
      setError("两次输入的密码不一致。");
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

  return (
    <AuthShell title="初始化认证中枢" subtitle="创建第一个管理员账户，之后才能开放注册与接入">
      {success ? (
        <div
          role="status"
          className="mt-7 rounded-lg border border-emerald-500/25 bg-emerald-500/[0.07] p-5 text-center"
        >
          <CheckCircle2 className="mx-auto text-emerald-400" size={26} />
          <div className="mt-3 text-sm font-medium text-emerald-100">初始化完成</div>
          <div className="mt-1 text-xs text-emerald-200/70">正在跳转到登录页…</div>
        </div>
      ) : (
        <form className="mt-6 space-y-4" onSubmit={submit}>
          {error && <Notice tone="error">{error}</Notice>}
          <Field
            label="管理员用户名"
            icon={<UserRound size={15} />}
            type="text"
            autoComplete="username"
            required
            minLength={3}
            maxLength={64}
            placeholder="chenxing-owner"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
          <Field
            label="邮箱"
            icon={<Mail size={15} />}
            type="email"
            autoComplete="email"
            required
            placeholder="owner@example.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
          />
          <Field
            label="密码"
            icon={<LockKeyhole size={15} />}
            type="password"
            autoComplete="new-password"
            required
            minLength={10}
            placeholder="至少 10 个字符"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <Field
            label="确认密码"
            icon={<KeyRound size={15} />}
            type="password"
            autoComplete="new-password"
            required
            minLength={10}
            placeholder="再次输入密码"
            value={confirmation}
            onChange={(event) => setConfirmation(event.target.value)}
          />
          <Notice>
            该账户将获得 Owner 权限。初始化完成后，新的管理员只能由已登录的管理员创建。
          </Notice>
          <GlowButton className="w-full" type="submit" disabled={busy}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>完成初始化 <ArrowRight size={15} /></>}
          </GlowButton>
        </form>
      )}
    </AuthShell>
  );
}
