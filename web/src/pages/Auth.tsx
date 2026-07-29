import { FormEvent, ReactNode, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, Loader2, LockKeyhole, Mail, ShieldCheck, UserRound } from "lucide-react";
import { Field, GlowButton, Logo, Notice } from "../components/ui";
import { TotpSetupPanel } from "../components/TotpSetupPanel";
import { BRAND } from "../data/mock";
import { errorMessage, TotpSetupResponse } from "../api";
import { LoginResult, useStore } from "../store";

/** Carries request_id through login/register so an interrupted OAuth flow can resume. */
function requestQuery(requestId: string | null) {
  return requestId ? `?request_id=${encodeURIComponent(requestId)}` : "";
}

export function AuthShell({ children, title, subtitle }: { children: ReactNode; title: string; subtitle: string }) {
  return (
    <div className="flex min-h-screen bg-app">
      <div className="relative hidden w-[42%] flex-col justify-between border-r border-hairline p-10 lg:flex">
        <div className="aurora left-[-20%] top-[-10%] h-[420px] w-[420px] bg-indigo-600/15" />
        <Link to="/" className="relative flex items-center gap-2.5">
          <Logo size={30} />
          <span className="leading-tight">
            <span className="block text-sm font-semibold text-white">{BRAND.name}</span>
            <span className="block text-[10px] text-slate-500">{BRAND.platform}</span>
          </span>
        </Link>

        <div className="relative">
          <h2 className="text-2xl font-semibold leading-snug text-white">
            一个账号，接入所有<br />天穹辰星子项目
          </h2>
          <p className="mt-3 max-w-sm text-sm leading-relaxed text-slate-400">
            辰星通行证统一管理你的身份与授权。每次第三方应用请求访问，你都会看到它要什么、可以随时收回。
          </p>
        </div>

        <div className="relative flex items-center gap-2 text-[11px] text-slate-600">
          <ShieldCheck size={13} /> OAuth 2.0 · OpenID Connect · HttpOnly Session
        </div>
      </div>

      <div className="flex flex-1 items-center justify-center p-6">
        <div className="w-full max-w-[380px]">
          <Link to="/" className="mb-7 flex items-center justify-center gap-2 lg:hidden">
            <Logo size={28} />
            <span className="text-sm font-semibold text-white">{BRAND.name}</span>
          </Link>

          <h1 className="text-lg font-semibold text-white">{title}</h1>
          <p className="mt-1.5 text-xs text-slate-500">{subtitle}</p>
          {children}
        </div>
      </div>
    </div>
  );
}

export function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { login, startTotpSetup, completeTotp } = useStore();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestId = params.get("request_id");
  const [pending, setPending] = useState<Extract<LoginResult, { status: string }> | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");

  const goNext = () => {
    if (requestId) {
      navigate(`/oauth/consent?request_id=${encodeURIComponent(requestId)}`);
    } else {
      navigate(params.get("return_to") || "/console");
    }
  };

  const handleLoginResult = async (result: LoginResult) => {
    if ("session_id" in result) {
      goNext();
      return;
    }
    setPending(result);
    if (result.status === "factor_setup_required") setTotpSetup(await startTotpSetup(result.login_ticket));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await handleLoginResult(await login(identifier, password));
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const finishTotp = async (event: FormEvent) => {
    event.preventDefault();
    if (!pending) return;
    setBusy(true);
    setError(null);
    try {
      await completeTotp(pending.login_ticket, code);
      goNext();
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell
      title="登录辰星通行证"
      subtitle={requestId ? "登录后继续完成授权确认" : "使用你的用户名或邮箱登录"}
    >
      {!pending ? (
        <form className="mt-6 space-y-4" onSubmit={submit}>
          {error && <Notice tone="error">{error}</Notice>}
          <Field
            label="用户名或邮箱"
            icon={<UserRound size={15} />}
            type="text"
            autoComplete="username"
            required
            placeholder="用户名或 you@example.com"
            value={identifier}
            onChange={(event) => setIdentifier(event.target.value)}
          />
          <Field
            label="密码"
            icon={<LockKeyhole size={15} />}
            type="password"
            autoComplete="current-password"
            required
            placeholder="输入密码"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
          <GlowButton className="w-full" type="submit" disabled={busy}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>登录 <ArrowRight size={15} /></>}
          </GlowButton>
        </form>
      ) : (
        <form className="mt-6 space-y-4" onSubmit={finishTotp}>
          {error && <Notice tone="error">{error}</Notice>}
          {totpSetup ? <TotpSetupPanel setup={totpSetup} /> : <Notice>请输入验证器中的当前六位验证码。</Notice>}
          <Field
            label="动态验证码"
            icon={<ShieldCheck size={15} />}
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            placeholder="6 位数字"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
          <GlowButton className="w-full" type="submit" disabled={busy || code.length !== 6}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>完成登录 <ArrowRight size={15} /></>}
          </GlowButton>
        </form>
      )}

      <p className="mt-6 text-center text-xs text-slate-500">
        还没有通行证？{" "}
        <Link to={`/register${requestQuery(requestId)}`} className="font-medium text-indigo-400 hover:text-indigo-300">
          创建账号
        </Link>
      </p>
    </AuthShell>
  );
}

export function Register() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { register, startTotpSetup, completeTotp } = useStore();
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const requestId = params.get("request_id");
  const [pending, setPending] = useState<Extract<LoginResult, { status: string }> | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");

  const goNext = () => {
    navigate(requestId ? `/oauth/consent?request_id=${encodeURIComponent(requestId)}` : "/console");
  };

  const handleLoginResult = async (result: LoginResult) => {
    if ("session_id" in result) {
      goNext();
      return;
    }
    setPending(result);
    if (result.status === "factor_setup_required") setTotpSetup(await startTotpSetup(result.login_ticket));
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await handleLoginResult(await register(username, email, password, name));
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const finishTotp = async (event: FormEvent) => {
    event.preventDefault();
    if (!pending) return;
    setBusy(true);
    setError(null);
    try {
      await completeTotp(pending.login_ticket, code);
      goNext();
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="创建辰星通行证" subtitle="一个账号，连接所有接入辰星的应用">
      {!pending ? (
        <form className="mt-6 space-y-4" onSubmit={submit}>
          {error && <Notice tone="error">{error}</Notice>}
          <Field
            label="用户名"
            icon={<UserRound size={15} />}
            autoComplete="username"
            required
            minLength={3}
            maxLength={64}
            placeholder="用于登录，创建后不可修改"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
          />
          <Field
            label="显示名称"
            icon={<UserRound size={15} />}
            autoComplete="name"
            placeholder="选填，可随时修改"
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
          <Field
            label="邮箱"
            icon={<Mail size={15} />}
            type="email"
            autoComplete="email"
            required
            placeholder="you@example.com"
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
            hint="密码以慢哈希保存。请使用与其他站点不同的独立密码。"
          />
          <GlowButton className="w-full" type="submit" disabled={busy}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>创建并登录 <ArrowRight size={15} /></>}
          </GlowButton>
        </form>
      ) : (
        <form className="mt-6 space-y-4" onSubmit={finishTotp}>
          {error && <Notice tone="error">{error}</Notice>}
          {totpSetup ? <TotpSetupPanel setup={totpSetup} /> : <Notice>请输入验证器中的当前六位验证码。</Notice>}
          <Field
            label="动态验证码"
            icon={<ShieldCheck size={15} />}
            inputMode="numeric"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            placeholder="6 位数字"
            value={code}
            onChange={(event) => setCode(event.target.value)}
          />
          <GlowButton className="w-full" type="submit" disabled={busy || code.length !== 6}>
            {busy ? <Loader2 size={16} className="animate-spin" /> : <>完成登录 <ArrowRight size={15} /></>}
          </GlowButton>
        </form>
      )}

      <p className="mt-6 text-center text-xs text-slate-500">
        已有通行证？{" "}
        <Link to={`/login${requestQuery(requestId)}`} className="font-medium text-indigo-400 hover:text-indigo-300">
          返回登录
        </Link>
      </p>
    </AuthShell>
  );
}
