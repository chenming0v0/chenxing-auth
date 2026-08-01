import { FormEvent, ReactNode, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ArrowRight, Fingerprint, KeyRound, Loader2, LockKeyhole, Mail, ShieldCheck, UserRound } from "lucide-react";
import { Field, GlowButton, Logo, Notice } from "../components/ui";
import { TotpSetupPanel } from "../components/TotpSetupPanel";
import { BRAND } from "../data/constants";
import { api, errorMessage, ExternalProvider, TotpSetupResponse } from "../api";
import { LoginResult, useStore } from "../store";
import { protocolUrl } from "../utils/endpoints";

/** Carries request_id through login/register so an interrupted OAuth flow can resume. */
function requestQuery(requestId: string | null) {
  return requestId ? `?request_id=${encodeURIComponent(requestId)}` : "";
}

/**
 * After a JSON login succeeds mid OAuth flow, the freshly-issued session must be
 * bound to the pending authorization request before the consent screen will
 * accept it. With no request_id this is a plain console login.
 */
async function continueAfterLogin(requestId: string | null, navigate: (to: string) => void, returnTo: string) {
  if (requestId) {
    await api.bindAuthorization(requestId);
    navigate(`/oauth/consent?request_id=${encodeURIComponent(requestId)}`);
  } else {
    navigate(returnTo);
  }
}

/** External identity-provider buttons. Full-page navigations into the server-run
 *  external OAuth flow, which returns to the SPA consent/login route. */
function ExternalLogins({ requestId }: { requestId: string | null }) {
  const [providers, setProviders] = useState<ExternalProvider[]>([]);
  useEffect(() => {
    void api.externalProviders().then(setProviders).catch(() => setProviders([]));
  }, []);
  if (providers.length === 0) return null;
  return (
    <div className="mt-6">
      <div className="flex items-center gap-3 text-[11px] text-slate-600">
        <span className="h-px flex-1 bg-hairline" /> 或使用外部账号 <span className="h-px flex-1 bg-hairline" />
      </div>
      <div className="mt-4 space-y-2.5">
        {providers.map((provider) => (
          <a
            key={provider.slug}
            href={protocolUrl(`/auth/external/${encodeURIComponent(provider.slug)}${requestQuery(requestId)}`)}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-hairline bg-white/[0.03] px-4 py-2.5 text-sm font-medium text-slate-300 transition-colors hover:border-slate-600 hover:bg-white/[0.06] hover:text-white"
          >
            <KeyRound size={15} /> 使用 {provider.name} 登录
          </a>
        ))}
      </div>
    </div>
  );
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

type PendingFactor = Extract<LoginResult, { status: string }>;

interface FactorFlow {
  pending: PendingFactor | null;
  totpSetup: TotpSetupResponse | null;
  usePasskey: boolean;
  busy: boolean;
  code: string;
  setCode: (value: string) => void;
  begin: (result: PendingFactor) => Promise<void>;
  submitTotp: (event: FormEvent) => Promise<void>;
  runPasskey: () => Promise<void>;
}

/**
 * Drives the second-factor step shared by login and register. A pending login
 * can require TOTP (verify existing, or first-time enrollment with a QR code) or
 * passkey (register when none exists, authenticate otherwise). `onDone` fires
 * once a session is issued — the caller decides where to go next.
 */
function useFactorFlow(opts: {
  requestId: string | null;
  onDone: () => void;
  startTotpSetup: (ticket: string) => Promise<TotpSetupResponse>;
  completeTotp: (ticket: string, code: string) => Promise<void>;
  registerPasskey: (ticket: string) => Promise<void>;
  loginPasskey: (ticket: string) => Promise<void>;
  setError: (value: string | null) => void;
}): FactorFlow {
  const [pending, setPending] = useState<PendingFactor | null>(null);
  const [totpSetup, setTotpSetup] = useState<TotpSetupResponse | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);

  // Prefer TOTP when available; fall back to passkey only when it's the sole method.
  const usePasskey = !!pending && !pending.methods.includes("totp") && pending.methods.includes("passkey");
  const isSetup = pending?.status === "factor_setup_required";

  const begin = async (result: PendingFactor) => {
    setPending(result);
    const passkeyOnly = !result.methods.includes("totp") && result.methods.includes("passkey");
    if (result.status === "factor_setup_required" && !passkeyOnly) {
      setTotpSetup(await opts.startTotpSetup(result.login_ticket));
    }
  };

  const submitTotp = async (event: FormEvent) => {
    event.preventDefault();
    if (!pending) return;
    setBusy(true);
    opts.setError(null);
    try {
      await opts.completeTotp(pending.login_ticket, code);
      opts.onDone();
    } catch (value) {
      opts.setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const runPasskey = async () => {
    if (!pending) return;
    setBusy(true);
    opts.setError(null);
    try {
      if (isSetup) await opts.registerPasskey(pending.login_ticket);
      else await opts.loginPasskey(pending.login_ticket);
      opts.onDone();
    } catch (value) {
      if (value instanceof Error && value.message === "passkey_cancelled") opts.setError("passkey 操作已取消，请重试。");
      else opts.setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return { pending, totpSetup, usePasskey, busy, code, setCode, begin, submitTotp, runPasskey };
}

function FactorStep({ factor, error }: { factor: FactorFlow; error: string | null }) {
  if (factor.usePasskey) {
    const isSetup = factor.pending?.status === "factor_setup_required";
    return (
      <div className="mt-6 space-y-4">
        {error && <Notice tone="error">{error}</Notice>}
        <div className="flex flex-col items-center rounded-xl border border-hairline bg-white/[0.02] px-6 py-8 text-center">
          <span className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-indigo-500/10 text-indigo-300">
            <Fingerprint size={24} />
          </span>
          <p className="text-sm font-medium text-white">{isSetup ? "注册 passkey" : "使用 passkey 登录"}</p>
          <p className="mt-1.5 text-xs leading-relaxed text-slate-500">
            {isSetup ? "使用设备的指纹、面容或安全密钥创建 passkey。" : "使用你的指纹、面容或安全密钥完成验证。"}
          </p>
        </div>
        <GlowButton className="w-full" type="button" disabled={factor.busy} onClick={() => void factor.runPasskey()}>
          {factor.busy ? <Loader2 size={16} className="animate-spin" /> : <>{isSetup ? "创建 passkey" : "验证 passkey"} <Fingerprint size={15} /></>}
        </GlowButton>
      </div>
    );
  }

  return (
    <form className="mt-6 space-y-4" onSubmit={factor.submitTotp}>
      {error && <Notice tone="error">{error}</Notice>}
      {factor.totpSetup ? <TotpSetupPanel setup={factor.totpSetup} /> : <Notice>请输入验证器中的当前六位验证码。</Notice>}
      <Field
        label="动态验证码"
        icon={<ShieldCheck size={15} />}
        inputMode="numeric"
        pattern="[0-9]{6}"
        maxLength={6}
        required
        placeholder="6 位数字"
        value={factor.code}
        onChange={(event) => factor.setCode(event.target.value)}
      />
      <GlowButton className="w-full" type="submit" disabled={factor.busy || factor.code.length !== 6}>
        {factor.busy ? <Loader2 size={16} className="animate-spin" /> : <>完成登录 <ArrowRight size={15} /></>}
      </GlowButton>
    </form>
  );
}

export function Login() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const requestId = params.get("request_id");
  const returnTo = params.get("return_to") || "/console";
  const externalError = params.get("external_error");
  const { login, startTotpSetup, completeTotp, registerPasskey, loginPasskey } = useStore();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(externalError ? "外部账号登录未完成，请重试或使用密码登录。" : null);

  const factor = useFactorFlow({
    requestId,
    onDone: () => void continueAfterLogin(requestId, navigate, returnTo),
    startTotpSetup,
    completeTotp,
    registerPasskey,
    loginPasskey,
    setError,
  });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await login(identifier, password);
      if ("session_id" in result) {
        await continueAfterLogin(requestId, navigate, returnTo);
      } else {
        await factor.begin(result);
      }
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
      {!factor.pending ? (
        <>
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
          <ExternalLogins requestId={requestId} />
        </>
      ) : (
        <FactorStep factor={factor} error={error} />
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
  const requestId = params.get("request_id");
  const { register, startTotpSetup, completeTotp, registerPasskey, loginPasskey } = useStore();
  const [username, setUsername] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const factor = useFactorFlow({
    requestId,
    onDone: () => void continueAfterLogin(requestId, navigate, "/console"),
    startTotpSetup,
    completeTotp,
    registerPasskey,
    loginPasskey,
    setError,
  });

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await register(username, email, password, name);
      if ("session_id" in result) {
        await continueAfterLogin(requestId, navigate, "/console");
      } else {
        await factor.begin(result);
      }
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthShell title="创建辰星通行证" subtitle="一个账号，连接所有接入辰星的应用">
      {!factor.pending ? (
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
        <FactorStep factor={factor} error={error} />
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
