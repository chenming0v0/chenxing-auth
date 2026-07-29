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
  /** Shown to the developer when registering a client. */
  desc: string;
  /** Shown to the end user on the consent screen. */
  consent: string;
}

/**
 * Mirrors `scopes_supported` in the OIDC discovery document (src/oauth.rs).
 * The authorize endpoint rejects anything outside this list, so do not add
 * entries here before the server supports them.
 */
export const SCOPES: ScopeDef[] = [
  { id: "openid", desc: "签发 ID Token，OIDC 流程必需", consent: "用于识别你的辰星通行证" },
  { id: "profile", desc: "在 UserInfo 返回 name 等公开资料 Claim", consent: "你的显示名称等公开资料" },
  { id: "email", desc: "在 UserInfo 返回 email Claim", consent: "你的邮箱地址" },
];

export const SCOPE_MAP = new Map(SCOPES.map((scope) => [scope.id, scope]));
