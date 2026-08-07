"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { auth, clearToken, setToken, type TokenResponse } from "@/lib/api";

interface User {
  analyst_id: string;
  email: string;
  display_name: string;
  role: string;
}

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, display_name: string, password: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<AuthCtx | null>(null);

export function useAuth(): AuthCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}

function storeUser(data: TokenResponse): User {
  setToken(data.access_token);
  return {
    analyst_id: data.analyst_id,
    email: data.email,
    display_name: data.display_name,
    role: data.role,
  };
}

export default function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Restore session from existing cookie on mount
  useEffect(() => {
    auth.me()
      .then((me) => setUser(me))
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const data = await auth.login({ email, password });
    setUser(storeUser(data));
  }, []);

  const register = useCallback(async (email: string, display_name: string, password: string) => {
    const data = await auth.register({ email, display_name, password });
    setUser(storeUser(data));
  }, []);

  const logout = useCallback(() => {
    clearToken();
    setUser(null);
    window.location.href = "/login";
  }, []);

  return (
    <Ctx.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </Ctx.Provider>
  );
}
