import { createContext, useContext, useEffect, useMemo, useState, ReactNode } from "react";
import { api, ApiError, LoginResponse, OAuthClient, PendingLoginResponse, TotpSetupResponse, UserProfile, UserSession } from "./api";

export type LoginResult = LoginResponse | PendingLoginResponse;

export interface AppUser extends UserProfile {
  name: string;
  color: string;
}

interface Store {
  user: AppUser | null;
  loading: boolean;
  error: string | null;
  clients: OAuthClient[];
  sessions: UserSession[];
  refresh: () => Promise<void>;
  login: (identifier: string, password: string) => Promise<LoginResult>;
  register: (username: string, email: string, password: string, displayName: string) => Promise<LoginResult>;
  startTotpSetup: (loginTicket: string) => Promise<TotpSetupResponse>;
  completeTotp: (loginTicket: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  updateProfile: (displayName: string) => Promise<void>;
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  revokeSession: (id: number) => Promise<void>;
  createClient: (input: { client_name: string; redirect_uris: string[]; scopes: string[] }) => Promise<OAuthClient & { client_secret: string }>;
  updateClient: (clientId: string, input: { client_name: string; redirect_uris: string[]; scopes: string[] }) => Promise<void>;
  setClientStatus: (clientId: string, status: "enable" | "disable") => Promise<void>;
  rotateClientSecret: (clientId: string) => Promise<string>;
  clearError: () => void;
}

const Ctx = createContext<Store>(null as unknown as Store);

function colorFor(value: string) {
  const colors = ["from-indigo-500 to-violet-600", "from-cyan-400 to-blue-600", "from-fuchsia-500 to-purple-700", "from-emerald-400 to-teal-600"];
  const hash = [...value].reduce((sum, char) => sum + char.charCodeAt(0), 0);
  return colors[hash % colors.length];
}

function mapUser(profile: UserProfile): AppUser {
  return { ...profile, name: profile.display_name || profile.username, color: colorFor(String(profile.id)) };
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AppUser | null>(null);
  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [sessions, setSessions] = useState<UserSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = async () => {
    setLoading(true);
    try {
      const profile = await api.me();
      const [clientResponse, sessionResponse] = await Promise.all([api.clients(), api.sessions()]);
      setUser(mapUser(profile));
      setClients(clientResponse.items);
      setSessions(sessionResponse.items);
      setError(null);
    } catch (value) {
      if (!(value instanceof ApiError) || value.status !== 401) setError(value instanceof Error ? value.message : "加载失败");
      setUser(null);
      setClients([]);
      setSessions([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void refresh(); }, []);

  const value = useMemo<Store>(() => ({
    user,
    loading,
    error,
    clients,
    sessions,
    refresh,
    login: async (identifier, password) => {
      const result = await api.login({ identifier, password });
      if ("session_id" in result) await refresh();
      return result;
    },
    register: async (username, email, password, displayName) => {
      await api.register({ username, email, password, display_name: displayName || undefined });
      return await (async () => {
        const result = await api.login({ identifier: username, password });
        if ("session_id" in result) await refresh();
        return result;
      })();
    },
    startTotpSetup: async (loginTicket) => api.totpSetup(loginTicket),
    completeTotp: async (loginTicket, code) => { await api.totpLogin(loginTicket, code); await refresh(); },
    logout: async () => {
      try { await api.logout(); } finally { setUser(null); setClients([]); setSessions([]); }
    },
    updateProfile: async (displayName) => { setUser(mapUser(await api.updateProfile(displayName))); },
    changePassword: async (currentPassword, newPassword) => { await api.changePassword(currentPassword, newPassword); setUser(null); setClients([]); setSessions([]); },
    revokeSession: async (id) => { await api.revokeSession(id); await refresh(); },
    createClient: async (input) => { const created = await api.createClient(input); setClients((current) => [created, ...current]); return created; },
    updateClient: async (clientId, input) => { await api.updateClient(clientId, input); await refresh(); },
    setClientStatus: async (clientId, status) => { await api.setClientStatus(clientId, status); setClients((current) => current.map((client) => client.client_id === clientId ? { ...client, status: status === "enable" ? "active" : "disabled" } : client)); },
    rotateClientSecret: async (clientId) => (await api.rotateClientSecret(clientId)).client_secret,
    clearError: () => setError(null),
  }), [user, loading, error, clients, sessions]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useStore = () => useContext(Ctx);
