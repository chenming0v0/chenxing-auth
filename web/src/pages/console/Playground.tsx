import { useEffect, useMemo, useState } from "react";
import { ExternalLink, Rocket, ShieldCheck, Trash2 } from "lucide-react";
import {
  EmptyState, GhostButton, GlowButton, Notice, PageFade, PageHeader, Section,
} from "../../components/ui";
import { CodeSample, CopyField } from "../../components/CopyField";
import { SCOPES } from "../../data/constants";
import { useStore } from "../../store";
import { cn } from "../../utils/cn";

const PKCE_PREFIX = "chenxing:pkce:";

function base64Url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function randomValue(size = 32) {
  const bytes = new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return base64Url(bytes);
}

async function pkceChallenge(verifier: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64Url(new Uint8Array(digest));
}

interface BuiltRequest {
  url: string;
  state: string;
  verifier: string;
  challenge: string;
  redirectUri: string;
  clientId: string;
  scopes: string[];
}

export default function Playground() {
  const { clients } = useStore();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [picked, setPicked] = useState<string[]>([]);
  const [built, setBuilt] = useState<BuiltRequest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const client = useMemo(
    () => clients.find((item) => item.id === selectedId) ?? clients[0],
    [clients, selectedId]
  );

  useEffect(() => {
    setPicked(client?.scopes ?? []);
    setBuilt(null);
    setError(null);
  }, [client]);

  const toggle = (scope: string) =>
    setPicked((current) =>
      current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope]
    );

  const build = async () => {
    if (!client) return;
    const redirectUri = client.redirect_uris[0];
    if (!redirectUri) {
      setError("当前应用没有配置回调地址，请先在「接入应用」中补齐。");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const verifier = randomValue(32);
      const state = randomValue(16);
      const challenge = await pkceChallenge(verifier);
      sessionStorage.setItem(
        `${PKCE_PREFIX}${state}`,
        JSON.stringify({ verifier, clientId: client.client_id })
      );
      const query = new URLSearchParams({
        client_id: client.client_id,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: picked.join(" "),
        state,
        code_challenge: challenge,
        code_challenge_method: "S256",
      });
      setBuilt({
        url: `${window.location.origin}/oauth/authorize?${query.toString()}`,
        state,
        verifier,
        challenge,
        redirectUri,
        clientId: client.client_id,
        scopes: picked,
      });
    } catch {
      setError("当前浏览器不支持 Web Crypto，无法生成 PKCE 参数。");
    } finally {
      setBusy(false);
    }
  };

  const discard = () => {
    if (built) sessionStorage.removeItem(`${PKCE_PREFIX}${built.state}`);
    setBuilt(null);
  };

  if (clients.length === 0) {
    return (
      <PageFade>
        <PageHeader title="授权测试" description="用真实的授权码 + PKCE 流程验证你的接入配置。" />
        <div className="panel rounded-xl">
          <EmptyState
            icon={<Rocket size={20} />}
            title="需要先注册一个应用"
            description="测试台会使用你应用的 Client ID 和回调地址来构造真实的授权请求。"
          />
        </div>
      </PageFade>
    );
  }

  return (
    <PageFade>
      <PageHeader
        title="授权测试"
        description="构造一个真实的授权请求。批准后浏览器会带 code 跳转到你配置的回调地址，令牌交换需在你的服务端完成。"
      />

      <div className="grid gap-6 lg:grid-cols-2">
        <Section title="1 · 构造授权请求" className="min-w-0">
          <div className="space-y-5">
            <label className="block">
              <span className="mb-1.5 block text-xs font-medium text-slate-400">应用</span>
              <select
                value={client?.id ?? ""}
                onChange={(event) => setSelectedId(Number(event.target.value))}
                className="field w-full cursor-pointer rounded-lg px-3 py-2.5 text-sm text-white focus:outline-none"
              >
                {clients.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.client_name}
                    {item.status !== "active" ? "（已停用）" : ""}
                  </option>
                ))}
              </select>
            </label>

            {client?.status !== "active" && (
              <Notice tone="warn">该应用已停用，授权端点会拒绝它的请求。</Notice>
            )}

            <div>
              <div className="mb-2 text-xs font-medium text-slate-400">Scope</div>
              <div className="flex flex-wrap gap-2">
                {SCOPES.filter((scope) => client?.scopes.includes(scope.id)).map((scope) => {
                  const active = picked.includes(scope.id);
                  return (
                    <button
                      key={scope.id}
                      type="button"
                      onClick={() => toggle(scope.id)}
                      aria-pressed={active}
                      className={cn(
                        "cursor-pointer rounded-md border px-2.5 py-1.5 font-mono text-[11.5px] transition-colors",
                        active
                          ? "border-indigo-500 bg-indigo-500/[0.12] text-indigo-200"
                          : "border-hairline text-slate-500 hover:border-slate-600 hover:text-slate-300"
                      )}
                    >
                      {scope.id}
                    </button>
                  );
                })}
              </div>
              <p className="mt-2 text-[11px] text-slate-500">
                只能请求该应用已注册的 Scope，多余的会被授权端点拒绝。
              </p>
            </div>

            <div>
              <div className="mb-1.5 text-xs font-medium text-slate-400">回调地址</div>
              <div className="code-block truncate rounded-lg px-3 py-2 text-[12.5px]">
                {client?.redirect_uris[0] ?? "未配置"}
              </div>
            </div>

            {error && <Notice tone="error">{error}</Notice>}

            <GlowButton className="w-full" onClick={() => void build()} disabled={busy}>
              <Rocket size={15} /> {busy ? "生成中…" : "生成授权请求"}
            </GlowButton>
          </div>
        </Section>

        <Section
          title="2 · 发起并交换令牌"
          className="min-w-0"
          actions={built && <GhostButton className="px-3 py-1.5 text-xs" onClick={discard}><Trash2 size={13} /> 丢弃</GhostButton>}
        >
          {!built ? (
            <EmptyState
              icon={<Rocket size={20} />}
              title="尚未生成请求"
              description="生成后这里会显示授权 URL、PKCE 参数，以及你的服务端交换令牌所需的示例请求。"
            />
          ) : (
            <div className="space-y-5">
              <CopyField label="授权 URL" value={built.url} />

              <div className="grid gap-3 sm:grid-cols-2">
                <CopyField label="state" value={built.state} />
                <CopyField label="code_challenge" value={built.challenge} hint="S256" />
              </div>

              <CopyField
                label="code_verifier"
                value={built.verifier}
                hint="单次使用 · 仅存于本页 sessionStorage"
              />

              <Notice tone="info">
                <span className="flex items-start gap-2">
                  <ShieldCheck size={14} className="mt-0.5 shrink-0 text-slate-500" />
                  verifier 不会发给授权端点，只在你的服务端交换令牌时提交，用于证明请求来自同一个客户端。
                </span>
              </Notice>

              <div>
                <div className="mb-2 text-xs font-medium text-slate-400">服务端交换令牌</div>
                <CodeSample
                  language="http"
                  code={[
                    "POST /oauth/token",
                    "Content-Type: application/x-www-form-urlencoded",
                    "",
                    "grant_type=authorization_code",
                    "&code=<回调里拿到的 code>",
                    `&redirect_uri=${built.redirectUri}`,
                    `&client_id=${built.clientId}`,
                    "&client_secret=<你的 Client Secret>",
                    `&code_verifier=${built.verifier}`,
                  ].join("\n")}
                />
              </div>

              <a
                href={built.url}
                className="btn-glow inline-flex w-full items-center justify-center gap-1.5 rounded-lg px-5 py-2.5 text-sm font-medium text-white"
              >
                <ExternalLink size={15} /> 打开授权页面
              </a>
              <p className="text-center text-[11px] text-slate-500">
                将跳转到真实的授权确认页，完成后回到 {built.redirectUri}
              </p>
            </div>
          )}
        </Section>
      </div>
    </PageFade>
  );
}
