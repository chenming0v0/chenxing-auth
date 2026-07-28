import { useState } from "react";
import { motion } from "framer-motion";
import {
  Users as UsersIcon, Search, ShieldAlert, ShieldCheck,
  MoreHorizontal, Snowflake, Flame, Download,
} from "lucide-react";
import { Avatar, Badge, PageFade, Stat, GhostButton } from "../../components/ui";
import { useStore } from "../../store";

export default function Users() {
  const { users, toggleUserStatus } = useStore();
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<"全部" | "正常" | "冻结" | "待验证">("全部");

  const list = users.filter(
    (u) =>
      (filter === "全部" || u.status === filter) &&
      (u.name.toLowerCase().includes(q.toLowerCase()) ||
        u.email.toLowerCase().includes(q.toLowerCase()) ||
        u.uid.toLowerCase().includes(q.toLowerCase()))
  );

  const tone = (s: string): "green" | "red" | "amber" =>
    s === "正常" ? "green" : s === "冻结" ? "red" : "amber";

  return (
    <PageFade>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="flex items-center gap-2.5 text-xl font-bold text-white">
            <UsersIcon size={20} className="text-indigo-300" /> 用户管理
          </h1>
          <p className="mt-1 text-sm text-slate-500">管理后台 · 平台全部通行证账户（{users.length}）</p>
        </div>
        <GhostButton><Download size={13} className="mr-1.5 inline" /> 导出 CSV</GhostButton>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat icon={<UsersIcon size={17} />} label="注册用户" value="1,804,229" sub="+2,318 今日" />
        <Stat icon={<ShieldCheck size={17} />} label="今日活跃" value="312,077" sub="+4.2%" />
        <Stat icon={<ShieldAlert size={17} />} label="风险账户" value="126" />
        <Stat icon={<Flame size={17} />} label="今日授权次数" value="98,441" sub="+11.9%" />
      </div>

      {/* toolbar */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="field flex w-full max-w-xs items-center gap-2 rounded-xl px-3.5 py-2.5">
          <Search size={14} className="text-slate-600" />
          <input
            value={q} onChange={(e) => setQ(e.target.value)}
            placeholder="搜索昵称 / 邮箱 / 辰星 ID"
            className="w-full bg-transparent text-sm text-white placeholder:text-slate-600 focus:outline-none"
          />
        </div>
        <div className="flex gap-1.5">
          {(["全部", "正常", "冻结", "待验证"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`cursor-pointer rounded-xl px-3.5 py-2 text-xs font-medium transition ${
                filter === f ? "bg-indigo-500/20 text-white" : "text-slate-500 hover:bg-white/5 hover:text-slate-300"
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* table */}
      <div className="glass overflow-hidden rounded-3xl">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead>
              <tr className="border-b border-white/6 text-[11px] uppercase tracking-wider text-slate-600">
                <th className="px-6 py-4 font-medium">用户</th>
                <th className="px-4 py-4 font-medium">辰星 ID</th>
                <th className="px-4 py-4 font-medium">角色</th>
                <th className="px-4 py-4 font-medium">状态</th>
                <th className="px-4 py-4 font-medium">授权应用</th>
                <th className="px-4 py-4 font-medium">最近活跃</th>
                <th className="px-4 py-4 font-medium">注册时间</th>
                <th className="px-4 py-4 text-right font-medium">操作</th>
              </tr>
            </thead>
            <tbody>
              {list.map((u, i) => (
                <motion.tr
                  key={u.id}
                  initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }}
                  className="border-b border-white/4 transition hover:bg-white/[0.025]"
                >
                  <td className="px-6 py-3.5">
                    <div className="flex items-center gap-3">
                      <Avatar name={u.name} color={u.color} size="sm" />
                      <div className="leading-tight">
                        <div className="font-medium text-white">{u.name}</div>
                        <div className="text-xs text-slate-500">{u.email}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3.5 font-mono text-xs text-cyan-300/80">{u.uid}</td>
                  <td className="px-4 py-3.5">
                    <Badge tone={u.role.includes("管理") ? "indigo" : u.role === "开发者" ? "cyan" : "slate"}>{u.role}</Badge>
                  </td>
                  <td className="px-4 py-3.5"><Badge tone={tone(u.status)}>{u.status}</Badge></td>
                  <td className="px-4 py-3.5 text-slate-400">{u.apps}</td>
                  <td className="px-4 py-3.5 text-xs text-slate-500">{u.lastActive}</td>
                  <td className="px-4 py-3.5 text-xs text-slate-500">{u.registered}</td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => toggleUserStatus(u.id)}
                        title={u.status === "冻结" ? "解冻账户" : "冻结账户"}
                        className={`cursor-pointer rounded-lg p-2 transition ${
                          u.status === "冻结"
                            ? "text-emerald-400 hover:bg-emerald-500/10"
                            : "text-slate-500 hover:bg-cyan-500/10 hover:text-cyan-300"
                        }`}
                      >
                        <Snowflake size={14} />
                      </button>
                      <button className="cursor-pointer rounded-lg p-2 text-slate-500 transition hover:bg-white/5 hover:text-white">
                        <MoreHorizontal size={14} />
                      </button>
                    </div>
                  </td>
                </motion.tr>
              ))}
              {list.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-6 py-14 text-center text-sm text-slate-600">
                    没有匹配的用户
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="flex items-center justify-between px-6 py-4 text-xs text-slate-600">
          <span>显示 {list.length} / {users.length} 位用户</span>
          <div className="flex gap-1">
            {["1", "2", "3", "…", "128"].map((p) => (
              <button key={p} className={`cursor-pointer rounded-lg px-3 py-1.5 transition ${p === "1" ? "bg-indigo-500/20 text-white" : "hover:bg-white/5 hover:text-slate-300"}`}>{p}</button>
            ))}
          </div>
        </div>
      </div>
    </PageFade>
  );
}
