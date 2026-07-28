import { FormEvent, useState } from "react";
import { Calendar, Check, Copy, KeyRound, LockKeyhole, LogOut, Mail, Save, Smartphone } from "lucide-react";
import { errorMessage, formatDate } from "../../api";
import { Avatar, Badge, Field, GlowButton, GhostButton, PageFade } from "../../components/ui";
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
    event.preventDefault(); setBusy(true); setError(null); setMessage(null);
    try { await updateProfile(name); setMessage("资料已更新"); } catch (value) { setError(errorMessage(value)); } finally { setBusy(false); }
  };
  const savePassword = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null); setMessage(null);
    try { await changePassword(currentPassword, newPassword); setCurrentPassword(""); setNewPassword(""); setMessage("密码已修改，所有旧 Session 已撤销，请重新登录"); } catch (value) { setError(errorMessage(value)); } finally { setBusy(false); }
  };
  const copyId = () => { void navigator.clipboard?.writeText(user.id); setMessage("用户 ID 已复制"); };

  return <PageFade>
    <div className="mb-6"><h1 className="text-xl font-bold text-white">通行证资料</h1><p className="mt-1 text-sm text-slate-500">管理公开身份信息、密码和当前登录 Session。</p></div>
    <div className="grid gap-6 lg:grid-cols-3">
      <section className="glass rounded-3xl p-7"><div className="flex flex-col items-center text-center"><Avatar name={user.name} color={user.color} size="xl" /><h2 className="mt-5 text-xl font-bold text-white">{user.name}</h2><div className="mt-1 text-sm text-slate-500">{user.email}</div><div className="mt-3"><Badge tone="green">{user.status === "active" ? "正常" : user.status}</Badge></div><button onClick={copyId} className="code-block mt-6 flex w-full cursor-pointer items-center justify-between rounded-xl px-4 py-3 text-left hover:border-indigo-400/40"><div><div className="text-[10px] uppercase tracking-widest text-slate-600">用户 ID</div><div className="mt-0.5 truncate font-mono text-xs text-cyan-300">{user.id}</div></div><Copy size={15} className="text-slate-500" /></button></div></section>
      <div className="space-y-6 lg:col-span-2">
        <section className="glass rounded-3xl p-7"><div className="mb-5 flex items-center gap-2 text-sm font-semibold text-white"><Mail size={16} className="text-indigo-300" />公开资料</div><form className="space-y-4" onSubmit={saveProfile}><Field label="邮箱（不可修改）" value={user.email} disabled /><Field label="显示名称" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} /><div className="flex justify-end"><GlowButton type="submit" disabled={busy}><Save size={14} className="mr-1.5 inline" />保存资料</GlowButton></div></form></section>
        <section className="glass rounded-3xl p-7"><div className="mb-5 flex items-center gap-2 text-sm font-semibold text-white"><LockKeyhole size={16} className="text-amber-300" />修改密码</div><form className="grid gap-4 sm:grid-cols-2" onSubmit={savePassword}><Field label="当前密码" type="password" required minLength={1} value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} /><Field label="新密码" type="password" required minLength={12} value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /><div className="sm:col-span-2 flex items-center justify-between gap-3"><span className="text-xs text-slate-600">修改后所有已登录设备都会退出。</span><GlowButton type="submit" disabled={busy}>更新密码</GlowButton></div></form></section>
      </div>
    </div>
    {(message || error) && <div role="status" className={`mt-6 rounded-xl border px-4 py-3 text-sm ${error ? "border-rose-400/20 bg-rose-500/10 text-rose-200" : "border-emerald-400/20 bg-emerald-500/10 text-emerald-200"}`}>{error ?? message}</div>}
    <section className="mt-6 glass rounded-3xl p-7"><div className="mb-5 flex items-center gap-2 text-sm font-semibold text-white"><Smartphone size={16} className="text-cyan-300" />登录 Session</div><div className="space-y-2">{sessions.map((session) => <div key={session.id} className="flex flex-wrap items-center gap-3 rounded-xl border border-white/6 bg-white/[0.02] px-4 py-3"><span className={`h-2 w-2 rounded-full ${session.current ? "bg-emerald-400" : "bg-slate-600"}`} /><div className="min-w-0 flex-1"><div className="font-mono text-xs text-slate-300">{session.id}</div><div className="mt-1 flex flex-wrap gap-3 text-[11px] text-slate-600"><span><Calendar size={11} className="mr-1 inline" />创建 {formatDate(session.created_at)}</span><span>过期 {formatDate(session.expires_at)}</span></div></div>{session.current ? <Badge tone="green"><Check size={11} />当前设备</Badge> : <GhostButton className="px-3 py-1.5" onClick={() => void revokeSession(session.id)}><LogOut size={12} className="mr-1 inline" />撤销</GhostButton>}</div>)}{sessions.length === 0 && <div className="py-6 text-center text-sm text-slate-600">暂无活跃 Session</div>}</div></section>
    <div className="mt-6 flex items-center gap-2 text-xs text-slate-600"><KeyRound size={13} className="text-indigo-300/70" />密码与 Session 由认证中枢统一管理，前端不会保存密码。</div>
  </PageFade>;
}
