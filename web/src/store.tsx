import { createContext, useContext, useState, ReactNode } from "react";
import {
  Account, ACCOUNTS, ConnectedApp, CONNECTED_APPS,
  OAuthClient, INITIAL_CLIENTS, AdminUser, ADMIN_USERS,
} from "./data/mock";

interface Store {
  user: Account | null;
  login: (a: Account) => void;
  logout: () => void;
  accounts: Account[];
  addAccount: (a: Account) => void;
  connections: ConnectedApp[];
  revoke: (id: string) => void;
  addConnection: (app: ConnectedApp) => void;
  clients: OAuthClient[];
  addClient: (c: OAuthClient) => void;
  removeClient: (id: string) => void;
  users: AdminUser[];
  toggleUserStatus: (id: string) => void;
}

const Ctx = createContext<Store>(null as unknown as Store);

export function StoreProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Account | null>(null);
  const [accounts, setAccounts] = useState<Account[]>(ACCOUNTS);
  const [connections, setConnections] = useState<ConnectedApp[]>(CONNECTED_APPS);
  const [clients, setClients] = useState<OAuthClient[]>(INITIAL_CLIENTS);
  const [users, setUsers] = useState<AdminUser[]>(ADMIN_USERS);

  return (
    <Ctx.Provider
      value={{
        user,
        login: (a) => setUser(a),
        logout: () => setUser(null),
        accounts,
        addAccount: (a) => setAccounts((p) => [a, ...p]),
        connections,
        revoke: (id) => setConnections((p) => p.filter((c) => c.id !== id)),
        addConnection: (app) =>
          setConnections((p) => (p.some((c) => c.id === app.id) ? p : [app, ...p])),
        clients,
        addClient: (c) => setClients((p) => [c, ...p]),
        removeClient: (id) => setClients((p) => p.filter((c) => c.id !== id)),
        users,
        toggleUserStatus: (id) =>
          setUsers((p) =>
            p.map((u) =>
              u.id === id ? { ...u, status: u.status === "冻结" ? "正常" : "冻结" } : u
            )
          ),
      }}
    >
      {children}
    </Ctx.Provider>
  );
}

export const useStore = () => useContext(Ctx);
