export const LOGO_URL = "https://i.stardots.io/chengming/StarDots-2026072800544604605.png";

export const BRAND = {
  name: "天穹辰星",
  platform: "辰星认证中枢",
  product: "辰星通行证",
  full: "天穹辰星 · 辰星认证中枢",
  en: "SkyVault Star · Star ID Hub",
};

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
