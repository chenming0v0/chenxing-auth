export const LOGO_URL = "https://i.stardots.io/chengming/StarDots-2026072800544604605.png";

export const BRAND = {
  name: "天穹辰星",
  platform: "辰星认证中枢",
  product: "辰星通行证",
  full: "天穹辰星 · 辰星认证中枢",
  en: "SkyVault Star · Star ID Hub",
};

export interface Account {
  id: string;
  name: string;
  email: string;
  color: string; // avatar gradient
  role: "owner" | "admin" | "user";
  uid: string;
}

export const ACCOUNTS: Account[] = [
  { id: "a1", name: "辰林", email: "chenlin@skyvault.star", color: "from-violet-500 to-indigo-600", role: "owner", uid: "SV-88014392" },
  { id: "a2", name: "HEI", email: "hei131419@skyvault.star", color: "from-cyan-400 to-blue-600", role: "admin", uid: "SV-88015520" },
  { id: "a3", name: "星野", email: "hoshino@skyvault.star", color: "from-fuchsia-500 to-purple-700", role: "user", uid: "SV-88017781" },
];

export interface ScopeDef {
  id: string;
  label: string;
  desc: string;
  sensitive?: boolean;
}

export const SCOPES: ScopeDef[] = [
  { id: "openid", label: "身份标识 (openid)", desc: "获取你的唯一辰星 ID，用于识别你的账户" },
  { id: "profile", label: "基本资料 (profile)", desc: "查看你的昵称、头像与公开个人信息" },
  { id: "email", label: "邮箱地址 (email)", desc: "查看你的主邮箱地址" },
  { id: "star.storage", label: "星辉云存储 (star.storage)", desc: "读取并管理你授权的云端文件", sensitive: true },
  { id: "star.orbit", label: "轨道数据 (star.orbit)", desc: "访问你的活动轨迹与使用统计", sensitive: true },
];

export interface ConnectedApp {
  id: string;
  name: string;
  icon: string; // emoji
  color: string;
  scopes: string[];
  grantedAt: string;
  lastUsed: string;
  publisher: string;
}

export const CONNECTED_APPS: ConnectedApp[] = [
  { id: "app1", name: "星图笔记", icon: "✦", color: "from-indigo-500 to-violet-600", scopes: ["openid", "profile", "email"], grantedAt: "2025-11-02", lastUsed: "2 小时前", publisher: "Starchart Labs" },
  { id: "app2", name: "云枢网盘", icon: "☁", color: "from-cyan-500 to-sky-600", scopes: ["openid", "profile", "star.storage"], grantedAt: "2025-09-18", lastUsed: "昨天", publisher: "Nimbus Core" },
  { id: "app3", name: "流萤音乐", icon: "♪", color: "from-fuchsia-500 to-pink-600", scopes: ["openid", "profile"], grantedAt: "2025-06-30", lastUsed: "3 天前", publisher: "Firefly Audio" },
  { id: "app4", name: "岚风天气", icon: "❋", color: "from-emerald-500 to-teal-600", scopes: ["openid", "star.orbit"], grantedAt: "2025-03-12", lastUsed: "1 个月前", publisher: "Stormline" },
];

export interface OAuthClient {
  id: string;
  name: string;
  clientId: string;
  secret: string;
  redirectUri: string;
  scopes: string[];
  status: "已上线" | "审核中" | "已停用";
  createdAt: string;
  calls30d: number;
}

export const INITIAL_CLIENTS: OAuthClient[] = [
  {
    id: "c1", name: "极光相册", clientId: "svs_live_9f2Ka7XmQ4", secret: "sk_9d41f8c2e5b7a3d6f0e9c8b7a6d5e4f3",
    redirectUri: "https://aurora.photos/oauth/callback", scopes: ["openid", "profile", "star.storage"],
    status: "已上线", createdAt: "2025-08-21", calls30d: 128430,
  },
  {
    id: "c2", name: "深空终端", clientId: "svs_test_2bQx8LmN0z", secret: "sk_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    redirectUri: "http://localhost:3000/callback", scopes: ["openid", "email"],
    status: "审核中", createdAt: "2026-01-04", calls30d: 3204,
  },
];

export interface AdminUser {
  id: string;
  name: string;
  email: string;
  uid: string;
  color: string;
  role: string;
  status: "正常" | "冻结" | "待验证";
  apps: number;
  lastActive: string;
  registered: string;
}

export const ADMIN_USERS: AdminUser[] = [
  { id: "u1", name: "辰林", email: "chenlin@skyvault.star", uid: "SV-88014392", color: "from-violet-500 to-indigo-600", role: "超级管理员", status: "正常", apps: 4, lastActive: "刚刚", registered: "2024-12-01" },
  { id: "u2", name: "HEI", email: "hei131419@skyvault.star", uid: "SV-88015520", color: "from-cyan-400 to-blue-600", role: "管理员", status: "正常", apps: 2, lastActive: "18 分钟前", registered: "2025-01-15" },
  { id: "u3", name: "星野", email: "hoshino@skyvault.star", uid: "SV-88017781", color: "from-fuchsia-500 to-purple-700", role: "用户", status: "正常", apps: 6, lastActive: "2 小时前", registered: "2025-03-08" },
  { id: "u4", name: "沐白", email: "mubai@skyvault.star", uid: "SV-88019233", color: "from-amber-400 to-orange-600", role: "用户", status: "待验证", apps: 0, lastActive: "1 天前", registered: "2026-02-11" },
  { id: "u5", name: "Kepler", email: "kepler@skyvault.star", uid: "SV-88020147", color: "from-emerald-400 to-teal-600", role: "用户", status: "冻结", apps: 1, lastActive: "12 天前", registered: "2025-07-22" },
  { id: "u6", name: "云澈", email: "yunche@skyvault.star", uid: "SV-88021568", color: "from-rose-400 to-red-600", role: "开发者", status: "正常", apps: 3, lastActive: "36 分钟前", registered: "2025-05-19" },
];

export function randomId(prefix: string) {
  const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for (let i = 0; i < 12; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return `${prefix}${s}`;
}
