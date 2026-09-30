import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { api, ensureCsrf, setSession, silentRefresh } from "./api";
import type { AuthenticatedUser, LoginResponse } from "./types";

type AuthState = {
  user: AuthenticatedUser | null;
  ready: boolean;
  login: (email: string, password: string) => Promise<AuthenticatedUser>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  has: (permission: string) => boolean;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthenticatedUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      await ensureCsrf();
      const ok = await silentRefresh();
      if (ok && !cancelled) {
        try {
          const me = await api<AuthenticatedUser>("/auth/me");
          if (!cancelled) setUser(me);
        } catch {
          setSession(null);
        }
      }
      if (!cancelled) setReady(true);
    })();
    const timer = window.setInterval(() => {
      void silentRefresh();
    }, 8 * 60 * 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    await ensureCsrf();
    const result = await api<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password, device_label: "CYBERTRACE console" }),
      skipAuth: true,
      skipRefresh: true,
    });
    setSession(result.access_token, result.csrf_token);
    setUser(result.user);
    return result.user;
  }, []);

  const logout = useCallback(async () => {
    try {
      await api("/auth/logout", { method: "POST" });
    } finally {
      setSession(null);
      setUser(null);
    }
  }, []);

  const refreshUser = useCallback(async () => {
    const me = await api<AuthenticatedUser>("/auth/me");
    setUser(me);
  }, []);

  const has = useCallback(
    (permission: string) => Boolean(user?.permissions.includes(permission)),
    [user],
  );

  const value = useMemo(
    () => ({ user, ready, login, logout, refreshUser, has }),
    [user, ready, login, logout, refreshUser, has],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
