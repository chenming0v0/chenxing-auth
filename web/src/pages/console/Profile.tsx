import { FormEvent, useState } from "react";
import { Check, LogOut, Save } from "lucide-react";
import { errorMessage, formatDate } from "../../api";
import {
  Avatar, Badge, Field, GhostButton, GlowButton, Notice, PageFade, PageHeader, Section,
} from "../../components/ui";
import { CopyField } from "../../components/CopyField";
import { useStore } from "../../store";

export default function Profile() {
  const { user, sessions, updateProfile, changePassword, revokeSession } = useStore();
  const [name, setName] = useState(user?.display_name ?? "");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!user) return null;

  const saveProfile = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await updateProfile(name);
      setMessage("资料已更新。");
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  const savePassword = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      await changePassword(currentPassword, newPassword);
      setCurrentPassword("");
      setNewPassword("");
      setMessage("密码已修改，所有会话已撤销，请重新登录。");
    } catch (value) {
      setError(errorMessage(value));
    } finally {
      setBusy(false);
    }
  };

  return (
    <PageFade>
      <PageHeader title="通行证资料" description="管理公开身份信息、密码和登录会话。" />

      {(message || error) && (
        <div className="mb-5">
          <Notice tone={error ? "error" : "success"}>{error ?? message}</Notice>
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-3">
        <Section className="lg:col-span-1">
          <div className="flex flex-col items-center text-center">
            <Avatar name={user.name} color={user.color} size="xl" />
            <h2 className="mt-4 text-base font-semibold text-white">{user.name}</h2>
            <div className="mt-1 text-xs text-slate-500">{user.email}</div>
            <div className="mt-3 flex items-center gap-2">
              <Badge tone={user.status === "active" ? "green" : "amber"}>
                {user.status === "active" ? "正常" : user.status}
              </Badge>
              <Badge>{user.role === "owner" ? "所有者" : user.role === "admin" ? "管理员" : "用户"}</Badge>
            </div>
          </div>
          <div className="mt-5 border-t border-hairline pt-5">
            <CopyField label="用户 ID" value={String(user.id)} hint="sub Claim" />
          </div>
        </Section>

        <div className="space-y-6 lg:col-span-2">
          <Section title="公开资料" description="显示名称会出现在授权确认页面上。">
            <form className="space-y-4" onSubmit={saveProfile}>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="用户名" value={user.username} disabled hint="创建后不可修改" />
                <Field label="邮箱" value={user.email} disabled hint="如需更换请联系管理员" />
              </div>
              <Field
                label="显示名称"
                value={name}
                maxLength={128}
                placeholder="留空则显示用户名"
                onChange={(event) => setName(event.target.value)}
              />
              <div className="flex justify-end border-t border-hairline pt-4">
                <GlowButton type="submit" disabled={busy}><Save size={14} /> 保存资料</GlowButton>
              </div>
            </form>
          </Section>

          <Section title="修改密码" description="修改后所有已登录设备都会退出，包括当前设备。">
            <form className="space-y-4" onSubmit={savePassword}>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field
                  label="当前密码"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={currentPassword}
                  onChange={(event) => setCurrentPassword(event.target.value)}
                />
                <Field
                  label="新密码"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={10}
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  hint="至少 10 个字符"
                />
              </div>
              <div className="flex justify-end border-t border-hairline pt-4">
                <GlowButton type="submit" disabled={busy}>更新密码</GlowButton>
              </div>
            </form>
          </Section>
        </div>
      </div>

      <Section
        className="mt-6"
        title="登录会话"
        description="每个会话对应一台设备的登录状态。撤销后该设备需要重新登录。"
      >
        {sessions.length === 0 ? (
          <p className="py-4 text-center text-xs text-slate-500">暂无活跃会话</p>
        ) : (
          <div className="space-y-2">
            {sessions.map((session) => (
              <div
                key={session.id}
                className="flex flex-wrap items-center gap-3 rounded-lg border border-hairline px-3.5 py-3"
              >
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${session.current ? "bg-emerald-400" : "bg-slate-600"}`} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-slate-300">
                    会话 <span className="font-mono">#{session.id}</span>
                  </div>
                  <div className="mt-0.5 text-[11px] text-slate-500">
                    创建于 {formatDate(session.created_at)} · 过期 {formatDate(session.expires_at)}
                  </div>
                </div>
                {session.current ? (
                  <Badge tone="green"><Check size={11} /> 当前设备</Badge>
                ) : (
                  <GhostButton
                    className="px-3 py-1.5 text-xs"
                    onClick={() => void revokeSession(session.id)}
                  >
                    <LogOut size={12} /> 撤销
                  </GhostButton>
                )}
              </div>
            ))}
          </div>
        )}
      </Section>
    </PageFade>
  );
}
