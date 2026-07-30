import { FormEvent, useState } from "react";
import {
  AlertTriangle, Check, Code2, KeyRound, Loader2, Pencil, Plus, Power, RefreshCw,
} from "lucide-react";
import { errorMessage, OAuthClient, RegisteredOAuthClient } from "../../api";
import {
  Badge, EmptyState, Field, GhostButton, GlowButton, IconButton, Modal, Notice,
  PageFade, PageHeader, Section, TextArea,
} from "../../components/ui";
import { CopyField, EndpointRow } from "../../components/CopyField";
import { SCOPES } from "../../data/constants";
import { useStore } from "../../store";
import { cn } from "../../utils/cn";

const CLIENT_LIMIT = 2;

/** Endpoints follow the browser origin, which is the issuer for a same-origin console. */
function endpoints() {
  const origin = window.location.origin;
  return [
    { label: "Discovery", method: "GET", url: `${origin}/.well-known/openid-configuration` },
    { label: "JWKS", method: "GET", url: `${origin}/.well-known/jwks.json` },
    { label: "Authorization", method: "GET", url: `${origin}/oauth/authorize` },
    { label: "Token", method: "POST", url: `${origin}/oauth/token` },
    { label: "UserInfo", method: "GET", url: `${origin}/oauth/userinfo` },
    { label: "Revocation", method: "POST", url: `${origin}/oauth/revoke` },
  ];
}

export default function Developer() {
  const { clients, createClient, updateClient, setClientStatus, rotateClientSecret } = useStore();
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<OAuthClient | null>(null);
  const [credentials, setCredentials] = useState<RegisteredOAuthClient | null>(null);
  const [name, setName] = useState("");
  const [uris, setUris] = useState("");
  const [picked, setPicked] = useState<string[]>(["openid", "profile"]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const atLimit = clients.length >= CLIENT_LIMIT;

  const closeForm = () => {
    setFormOpen(false);
    setEditing(null);
    setName("");
    setUris("");
    setPicked(["openid", "profile"]);
    setError(null);
  };

  const openCreate = () => {
    closeForm();
    setFormOpen(true);
  };

  const openEdit = (client: OAuthClient) => {
    setEditing(client);
    setName(client.client_name);
    setUris(client.redirect_uris.join("\n"));
    setPicked(client.scopes);
    setError(null);
    setFormOpen(true);
  };

  const togglePicked = (scope: string) =>
    setPicked((current) =>
      current.includes(scope) ? current.filter((item) => item !== scope) : [...current, scope]
    );

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    const input = {
      client_name: name.trim(),
      redirect_uris: uris.split(/\r?\n|,/).map((value) => value.trim()).filter(Boolean),
      scopes: picked.length ? picked : ["openid"],
    };
    try {
      if (editing) {
        await updateClient(editing.client_id, input);
        closeForm();
      } else {
        const created = await createClient(input);
        closeForm();
        setCredentials(created);
      }
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const rotate = async (client: OAuthClient) => {
    setBusy(true);
    setError(null);
    try {
      const secret = await rotateClientSecret(client.client_id);
      setCredentials({ ...client, client_secret: secret });
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageFade>
      <PageHeader
        title="接入应用"
        description="注册 OAuth Client，让你的项目支持「使用辰星通行证登录」。授权码流程需要 PKCE（S256）。"
        actions={
          <GlowButton onClick={openCreate} disabled={atLimit}>
            <Plus size={15} /> 注册应用
          </GlowButton>
        }
      />

      {error && !formOpen && (
        <div className="mb-5">
          <Notice tone="error">{error}</Notice>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="min-w-0 space-y-5 lg:col-span-2">
          {clients.length === 0 ? (
            <div className="panel rounded-xl">
              <EmptyState
                icon={<Code2 size={20} />}
                title="还没有注册应用"
                description="注册后你会得到一组 Client ID 与 Client Secret，用于向认证中枢发起授权码流程。"
                action={<GlowButton onClick={openCreate}><Plus size={15} /> 注册应用</GlowButton>}
              />
            </div>
          ) : (
            clients.map((client) => (
              <ClientCard
                key={client.id}
                client={client}
                busy={busy}
                onEdit={() => openEdit(client)}
                onToggle={() => void setClientStatus(client.client_id, client.status === "active" ? "disable" : "enable")}
                onRotate={() => void rotate(client)}
              />
            ))
          )}

          <p className="text-xs text-slate-500">
            已使用 {clients.length} / {CLIENT_LIMIT} 个应用配额
            {atLimit && " · 已达上限，如需更多请联系管理员"}
          </p>
        </div>

        <aside className="min-w-0 space-y-5">
          <Section
            title="服务端点"
            description="已在 OIDC Discovery 文档公布，客户端库可自动发现。"
          >
            <div className="-mx-5 -my-5">
              {endpoints().map((endpoint) => (
                <EndpointRow key={endpoint.label} {...endpoint} />
              ))}
            </div>
          </Section>

          <Section title="协议支持">
            <dl className="space-y-3 text-xs">
              <SpecRow label="授权类型" value="authorization_code" />
              <SpecRow label="Response Type" value="code" />
              <SpecRow label="PKCE" value="S256（必需）" />
              <SpecRow label="ID Token 签名" value="RS256" />
              <SpecRow label="支持 Scope" value={SCOPES.map((scope) => scope.id).join(" ")} />
            </dl>
          </Section>
        </aside>
      </div>

      <Modal
        open={formOpen}
        onClose={closeForm}
        wide
        title={editing ? "编辑应用" : "注册应用"}
        description={editing ? `修改 ${editing.client_name} 的名称、回调地址与 Scope。` : "填写基本信息后，系统会生成一组客户端凭据。"}
      >
        <form className="space-y-5" onSubmit={submit}>
          <Field
            label="应用名称"
            required
            maxLength={128}
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="例如：星图笔记"
            hint="会显示在用户的授权确认页面上。"
          />

          <TextArea
            label="回调地址（每行一个）"
            required
            rows={3}
            value={uris}
            onChange={(event) => setUris(event.target.value)}
            placeholder="https://example.com/oauth/callback"
            hint="必须与授权请求中的 redirect_uri 完全一致，包括协议、端口和路径。"
          />

          <div>
            <div className="mb-2 text-xs font-medium text-slate-400">请求的 Scope</div>
            <div className="space-y-2">
              {SCOPES.map((scope) => {
                const active = picked.includes(scope.id);
                return (
                  <button
                    type="button"
                    key={scope.id}
                    onClick={() => togglePicked(scope.id)}
                    aria-pressed={active}
                    className={cn(
                      "flex w-full cursor-pointer items-start gap-3 rounded-lg border px-3.5 py-3 text-left transition-colors",
                      active ? "border-indigo-500 bg-indigo-500/[0.08]" : "border-hairline hover:border-slate-600"
                    )}
                  >
                    <span
                      className={cn(
                        "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border",
                        active ? "border-indigo-500 bg-indigo-500 text-white" : "border-slate-600"
                      )}
                    >
                      {active && <Check size={11} />}
                    </span>
                    <span className="min-w-0">
                      <span className="block font-mono text-xs text-slate-200">{scope.id}</span>
                      <span className="mt-0.5 block text-[11px] leading-relaxed text-slate-500">{scope.desc}</span>
                    </span>
                  </button>
                );
              })}
            </div>
            {!picked.includes("openid") && (
              <div className="mt-2.5">
                <Notice tone="warn">未勾选 openid 时不会签发 ID Token，OIDC 客户端库通常无法完成登录。</Notice>
              </div>
            )}
          </div>

          {error && <Notice tone="error">{error}</Notice>}

          <div className="flex justify-end gap-2 border-t border-hairline pt-4">
            <GhostButton type="button" onClick={closeForm}>取消</GhostButton>
            <GlowButton type="submit" disabled={busy}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : editing ? <Pencil size={14} /> : <Plus size={15} />}
              {editing ? "保存修改" : "注册应用"}
            </GlowButton>
          </div>
        </form>
      </Modal>

      <Modal
        open={Boolean(credentials)}
        onClose={() => setCredentials(null)}
        wide
        title="客户端凭据"
        description="Client Secret 只在此刻返回一次，关闭后无法再次查看。"
      >
        {credentials && (
          <div className="space-y-4">
            <Notice tone="warn">
              <span className="flex items-start gap-2">
                <AlertTriangle size={14} className="mt-0.5 shrink-0" />
                请立即保存 Secret 并存放在服务端。若丢失，只能轮换出新的 Secret。
              </span>
            </Notice>
            <CopyField label="Client ID" value={credentials.client_id} />
            <CopyField label="Client Secret" value={credentials.client_secret} secret hint="仅显示一次" />
            <div className="flex justify-end border-t border-hairline pt-4">
              <GlowButton onClick={() => setCredentials(null)}>我已保存</GlowButton>
            </div>
          </div>
        )}
      </Modal>
    </PageFade>
  );
}

function SpecRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="shrink-0 text-slate-500">{label}</dt>
      <dd className="min-w-0 text-right font-mono text-[11.5px] text-slate-300">{value}</dd>
    </div>
  );
}

function ClientCard({
  client, onEdit, onToggle, onRotate, busy,
}: { client: OAuthClient; onEdit: () => void; onToggle: () => void; onRotate: () => void; busy: boolean }) {
  const disabled = client.status !== "active";
  return (
    <div className="panel rounded-xl">
      <div className="flex items-start justify-between gap-4 border-b border-hairline px-5 py-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="truncate text-sm font-semibold text-white">{client.client_name}</h3>
            <Badge tone={disabled ? "slate" : "green"}>{disabled ? "已停用" : "启用中"}</Badge>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            {client.redirect_uris.length} 个回调地址 · {client.scopes.length} 个 Scope
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <IconButton title="编辑" onClick={onEdit}><Pencil size={14} /></IconButton>
          <IconButton title="轮换 Secret" onClick={onRotate} disabled={busy}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
          </IconButton>
          <IconButton
            title={disabled ? "启用" : "停用"}
            onClick={onToggle}
            className={disabled ? "" : "hover:bg-rose-500/10 hover:text-rose-300"}
          >
            <Power size={14} />
          </IconButton>
        </div>
      </div>

      <div className="space-y-4 p-5">
        <CopyField label="Client ID" value={client.client_id} />

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-400">回调地址</div>
          <div className="space-y-1.5">
            {client.redirect_uris.map((uri) => (
              <div key={uri} className="code-block truncate rounded-lg px-3 py-2 text-[12.5px]">{uri}</div>
            ))}
          </div>
        </div>

        <div>
          <div className="mb-1.5 text-xs font-medium text-slate-400">Scope</div>
          <div className="flex flex-wrap gap-1.5">
            {client.scopes.map((scope) => (
              <code key={scope} className="rounded-md border border-hairline px-2 py-1 font-mono text-[11px] text-slate-300">
                {scope}
              </code>
            ))}
          </div>
        </div>

        <div className="grid gap-4 border-t border-hairline pt-4 sm:grid-cols-2">
          <Quota label="今日调用" used={client.quota.daily_used} limit={client.quota.daily_limit} />
          <Quota label="本月调用" used={client.quota.monthly_used} limit={client.quota.monthly_limit} />
        </div>

        <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
          <KeyRound size={12} />
          Secret 以哈希形式保存，轮换后旧 Secret 立即失效。
        </div>
      </div>
    </div>
  );
}

function Quota({ label, used, limit }: { label: string; used: number; limit: number }) {
  const ratio = limit > 0 ? Math.min(1, used / limit) : 0;
  const high = ratio >= 0.9;
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between text-[11px]">
        <span className="text-slate-500">{label}</span>
        <span className={cn("font-mono tabular-nums", high ? "text-amber-300" : "text-slate-400")}>
          {used.toLocaleString()} / {limit.toLocaleString()}
        </span>
      </div>
      <div className="h-1 overflow-hidden rounded-full bg-white/[0.06]">
        <div
          className={cn("h-full rounded-full", high ? "bg-amber-400" : "bg-indigo-500")}
          style={{ width: `${ratio * 100}%` }}
        />
      </div>
    </div>
  );
}
