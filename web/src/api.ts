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
  id: string;
  email: string;
  display_name: string | null;
  status: string;
  current_session_expires_at: unknown;
}

export interface UserSession {
  id: string;
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
  id: string;
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

export interface AdminProfile {
  admin_id: string | null;
  email: string | null;
  role: string;
  permissions: string[];
  status: string;
}

export interface AdminOverview {
  users: number | null;
  oauth_clients: number | null;
  administrators: number | null;
  audit_events: number | null;
}

export interface AdminUser {
  id: string;
  email: string;
  display_name: string | null;
  status: string;
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
  register: (input: { email: string; password: string; display_name?: string }) =>
    request<{ user: { id: string } }>("/api/v1/users", { method: "POST", body: JSON.stringify(input) }),
  login: (input: { email: string; password: string }) =>
    request<{ session_id: string; expires_at: string }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify(input) }),
  logout: () => request<void>("/api/v1/auth/session", mutation({ method: "DELETE" })),
  me: () => request<UserProfile>("/api/v1/auth/me"),
  updateProfile: (display_name: string) =>
    request<UserProfile>("/api/v1/auth/me", mutation({ method: "PATCH", body: JSON.stringify({ display_name }) })),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/api/v1/auth/password", mutation({ method: "POST", body: JSON.stringify({ current_password, new_password }) })),
  sessions: () => request<{ items: UserSession[] }>("/api/v1/auth/sessions"),
  revokeSession: (id: string) => request<void>(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, mutation({ method: "DELETE" })),
  clients: () => request<{ items: OAuthClient[] }>("/api/v1/auth/oauth-clients"),
  createClient: (input: { client_name: string; redirect_uris: string[]; scopes: string[] }) =>
    request<RegisteredOAuthClient>("/api/v1/auth/oauth-clients", mutation({ method: "POST", body: JSON.stringify(input) })),
  updateClient: (id: string, input: { client_name: string; redirect_uris: string[]; scopes: string[] }) =>
    request<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(id)}`, mutation({ method: "PUT", body: JSON.stringify(input) })),
  setClientStatus: (id: string, status: "enable" | "disable") =>
    request<void>(`/api/v1/auth/oauth-clients/${encodeURIComponent(id)}/${status}`, mutation({ method: "POST" })),
  rotateClientSecret: (id: string) =>
    request<{ client_secret: string }>(`/api/v1/auth/oauth-clients/${encodeURIComponent(id)}/rotate-secret`, mutation({ method: "POST" })),
  pendingAuthorization: (id: string) =>
    request<PendingAuthorization>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(id)}`),
  decideAuthorization: (id: string, decision: "approve" | "deny") =>
    request<{ decision: string; redirect_to: string }>(`/api/v1/oauth/authorize/requests/${encodeURIComponent(id)}`, mutation({ method: "POST", body: JSON.stringify({ decision }) })),
  adminMe: () => request<AdminProfile>("/api/v1/admin/auth/me"),
  adminOverview: () => request<AdminOverview>("/api/v1/admin/overview"),
  adminUsers: (search = "", status = "") => request<PageResponse<AdminUser>>(`/api/v1/admin/users/query?page=1&page_size=100&search=${encodeURIComponent(search)}&status=${encodeURIComponent(status)}`),
  adminSetUserStatus: (id: string, status: "active" | "disabled") =>
    request<void>(`/api/v1/admin/users/${encodeURIComponent(id)}/${status}`, mutation({ method: "POST" })),
};

export function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.code === "invalid_credentials") return "邮箱或密码不正确";
    if (error.code === "email_already_registered") return "这个邮箱已经注册";
    if (error.code === "oauth_client_quota_exceeded") return "最多创建 2 个 OAuth 应用";
    if (error.code === "csrf_invalid") return "页面安全校验已失效，请刷新后重试";
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
