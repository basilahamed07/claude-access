import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ApiProblem, api, setCsrf, setUnauthorizedHandler, type Schemas } from "./client";

export type Me = Schemas["MeResponse"];
export type Role = "viewer" | "analyst" | "admin";
const RANK: Record<Role, number> = { viewer: 0, analyst: 1, admin: 2 };

interface SessionValue { me: Me | null; loading: boolean; can: (role: Role) => boolean; logout: () => Promise<void> }
const Ctx = createContext<SessionValue>({ me: null, loading: true, can: () => false, logout: async () => {} });
export const useSession = () => useContext(Ctx);

export function loginUrl(next: string): string {
  const safe = next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/login") ? next : "/";
  return safe === "/" ? "/login" : `/login?next=${encodeURIComponent(safe)}`;
}

/** Only same-origin paths are followed after login. */
export function safeNext(raw: string | null): string {
  return raw && raw.startsWith("/") && !raw.startsWith("//") && !raw.startsWith("/login") ? raw : "/";
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const location = useLocation();
  const q = useQuery({
    queryKey: ["me"],
    retry: false,
    staleTime: 60_000,
    queryFn: async () => {
      try {
        const me = await api<Me>("GET", "/v1/auth/me", { quiet: true });
        setCsrf(me.csrf_token);
        return me;
      } catch (e) {
        if (e instanceof ApiProblem && e.status === 401) return null;
        throw e;
      }
    },
  });

  useEffect(() => {
    setUnauthorizedHandler((path) => {
      qc.setQueryData(["me"], null);
      navigate(loginUrl(path), { replace: true });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate, qc]);

  const me = q.data ?? null;
  const value = useMemo<SessionValue>(() => ({
    me,
    loading: q.isLoading,
    can: (role) => me !== null && RANK[me.role as Role] >= RANK[role],
    logout: async () => {
      try { await api("POST", "/v1/auth/logout", { body: {}, quiet: true }); } catch { /* already signed out */ }
      setCsrf(null);
      qc.clear();
      qc.setQueryData(["me"], null);
      navigate("/login", { replace: true });
    },
  }), [me, q.isLoading, qc, navigate]);
  void location;
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
