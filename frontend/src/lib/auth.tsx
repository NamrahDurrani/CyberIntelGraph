"use client";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, token } from "./api";
import type { User } from "./types";

interface Auth { user: User | null; loading: boolean; signIn: (t: string, u: User) => void; signOut: () => void; setUser: (u: User) => void }
const Ctx = createContext<Auth>(null!);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    if (!token.get()) { setLoading(false); return; }
    api<User>("/api/auth/me").then(setUser).catch(() => token.clear()).finally(() => setLoading(false));
  }, []);
  const signIn = useCallback((t: string, u: User) => { token.set(t); setUser(u); }, []);
  const signOut = useCallback(() => { token.clear(); setUser(null); }, []);
  return <Ctx.Provider value={{ user, loading, signIn, signOut, setUser }}>{children}</Ctx.Provider>;
}
