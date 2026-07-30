export interface ApiErrorShape {
  code: string;
  message: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, error: ApiErrorShape) {
    super(error.message);
    this.name = "ApiError";
    this.status = status;
    this.code = error.code;
  }
}

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  display_name: string | null;
  status: string;
  role: "user" | "admin" | "owner";
  current_session_expires_at: unknown;
}

export interface UserSession {
  id: number;
  created_at: unknown;
  expires_at: unknown;
  current: boolean;
}

export interface QuotaSnapshot {
  daily_limit: number;
  daily_used: number;
  monthly_limit: number;
  monthly_used: number;
}

export interface OAuthClient {
  id: number;
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  scopes: string[];
  status: "active" | "disabled" | string;
  quota: QuotaSnapshot;
}

export interface RegisteredOAuthClient extends OAuthClient {
  client_secret: string;
}

export interface PendingAuthorization {
  request_id: string;
  client_id: string;
  client_name: string;
  redirect_host: string;
  scopes: string[];
  expires_in: number;
}

export interface AdminOverview {
  users: number | null;
  oauth_clients: number | null;
  administrators: number | null;
  audit_events: number | null;
}

export interface BootstrapStatus {
  initialized: boolean;
}

export interface PendingLoginResponse {
  status: "factor_setup_required" | "factor_required";
  login_ticket: string;
  methods: Array<"totp" | "passkey">;
}

export interface LoginResponse {
  session_id: string;
  expires_at: unknown;
}

export interface TotpSetupResponse {
  secret_base32: string;
  otpauth_url: string;
}

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  display_name: string | null;
  status: string;
  role: "user" | "admin" | "owner";
  created_at: unknown;
}

interface PageResponse<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
}

function csrfCookie(name = "chenxing_csrf") {
  return document.cookie
    .split(";")
    .map((part) => part.trim())
    .find((part) => part.startsWith(`${name}=`))
    ?.slice(name.length + 1) ?? "";
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  const response = await fetch(path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    let error: ApiErrorShape = { code: "request_failed", message: `请求失败（${response.status}）` };
    try {
      error = await response.json() as ApiErrorShape;
    } catch {
      // Keep the generic message when the server did not return JSON.
    }
    throw new ApiError(response.status, error);
  }
  if (response.status === 204) return undefined as T;
  return await response.json() as T;
}

function mutation(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  headers.set("X-CSRF-Token", csrfCookie());
  return { ...init, headers };
}

export const api = {
  bootstrapStatus: () => request<BootstrapStatus>("/api/v1/admin/bootstrap/status"),
  bootstrapAdmin: (input: { username: string; email: string; password: string }) =>
    request<{ id: number; role: string }>("/api/v1/admin/bootstrap", { method: "POST", body: JSON.stringify(input) }),
  register: (input: { username: string; email: string; password: string; display_name?: string }) =>
    request<{ user: { id: number } }>("/api/v1/users", { method: "POST", body: JSON.stringify(input) }),
  login: (input: { identifier: string; password: string; totp_code?: string }) =>
    request<LoginResponse | PendingLoginResponse>("/api/v1/auth/login", { method: "POST", body: JSON.stringify(input) }),
  totpSetup: (login_ticket: string) =>
    request<TotpSetupResponse>("/api/v1/auth/totp/setup", { method: "POST", body: JSON.stringify({ login_ticket }) }),
  totpLogin: (login_ticket: string, code: string) =>
    request<LoginResponse>("/api/v1/auth/totp/login", { method: "POST", body: JSON.stringify({ login_ticket, code }) }),
  logout: () => request<void>("/api/v1/auth/session", mutation({ method: "DELETE" })),
  me: () => request<UserProfile>("/api/v1/auth/me"),
  updateProfile: (display_name: string) =>
    request<UserProfile>("/api/v1/auth/me", mutation({ method: "PATCH", body: JSON.stringify({ display_name }) })),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/v1/auth/password", mutation({ method: "POST", body: JSON.stringify({ current_password, new_password }) })),
  sessions: () => request<{ items: UserSession[] }>("/api/v1/auth/sessions"),
  revokeSession: (id: number) => request<void>(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, mutation({ method: "DELETE" })),
  clients: () => request<{ items: OAuthClient[] }>("/api/v1/auth/oauth-clients"),
  createClient: (input: { client_name: string; redirect_uris: string[]; scopes: string[] }) =>
    request<RegisteredOAuthClient>("/api/v1/auth/oauth-clients", mutation({ method: "POST", body: JSON.stringify(input) })),
  updateClient: (client_id: string, input: { client_name: string; redirect_uris: string[]; scopes: string[] }) =>
    request<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client_id)}`, mutation({ method: "PUT", body: JSON.stringify(input) })),
  setClientStatus: (client_id: string, status: "enable" | "disable") =>
    request<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client_id)}/${status}`, mutation({ method: "POST" })),
  rotateClientSecret: (client_id: string) =>
    request<{ client_secret: string }>(`/api/v1/auth/oauth-clients/${encodeURIComponent(client_id)}/rotate-secret`, mutation({ method: "POST" })),
  pendingAuthorization: (id: string) =>
    request<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(id)}`),
  decideAuthorization: (id: string, decision: "approve" | "deny") =>
    request<{ decision: string; redirect_to: string }>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(id)}`, mutation({ method: "POST", body: JSON.stringify({ decision }) })),
  adminRegistrationEmail: () => request<{ registration_email_from: string | null }>("/api/v1/admin/settings/registration-email"),
  updateAdminRegistrationEmail: (registration_email_from: string | null) =>
    request<{ registration_email_from: string | null }>("/api/v1/admin/settings/registration-email", mutation({ method: "PUT", body: JSON.stringify({ registration_email_from }) })),
  adminOverview: () => request<AdminOverview>("/api/v1/admin/overview"),
  adminUsers: (search = "", status = "") => request<PageResponse<AdminUser>>(`/api/v1/admin/users/query?page=1&page_size=100&search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}`),
  adminSetUserStatus: (id: number, status: "active" | "disabled") =>
    request<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/${status}`, mutation({ method: "POST" })),
  adminSetUserRole: (id: number, role: "user" | "admin" | "owner") =>
    request<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/role`, mutation({ method: "POST", body: JSON.stringify({ role }) })),
};

export function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "invalid_credentials") return "用户名、邮箱或密码不正确";
    if (error.code === "bootstrap_already_completed") return "初始化已经完成，请使用通行证登录";
    if (error.code === "owner_bootstrap_requires_empty_database") return "数据库已有用户但没有 Owner，请清空开发数据后重新初始化";
    if (error.code === "invalid_username") return "请输入有效的用户名";
    if (error.code === "password_too_short") return "密码至少需要 10 个字符";
    if (error.code === "email_already_registered") return "这个邮箱已经注册";
    if (error.code === "username_already_registered") return "这个用户名已经注册";
    if (error.code === "oauth_client_quota_exceeded") return "最多创建 2 个 OAuth 应用";
    if (error.code === "csrf_invalid") return "页面安全校验已失效，请刷新后重试";
    if (error.code === "csrf_required") return "页面安全校验已失效，请刷新后重试";
    if (error.code === "invalid_email") return "请输入有效的邮箱地址";
    if (error.code === "invalid_factor") return "验证码不正确，请重新输入";
    if (error.code === "invalid_login_ticket") return "登录已超时，请重新输入密码登录";
    if (error.code === "user_disabled") return "这个账号已被停用，请联系管理员";
    if (error.code === "invalid_display_name" || error.code === "display_name_too_long") return "显示名称不合法或过长";
    return error.message;
  }
  return "网络暂时不可用，请稍后重试";
}

export function formatDate(value: unknown) {
  if (Array.isArray(value) && value.length >= 6) {
    const [year, ordinal, hour, minute, second, nanosecond] = value.map(Number);
    const date = new Date(Date.UTC(year, 0, ordinal, hour, minute, second, Math.floor(nanosecond / 1_000_000)));
    return Number.isNaN(date.getTime()) ? "时间未知" : date.toLocaleString("zh-CN");
  }
  if (typeof value !== "string") return "时间未知";
  const date = new Date(value.replace(" ", "T").replace(" +", "+"));
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN");
}
