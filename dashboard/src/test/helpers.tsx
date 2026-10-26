import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { SessionProvider } from "../api/session";
import { ToastProvider } from "../ui/toast";

export function json(body: unknown, init: { status?: number; headers?: Record<string, string> } = {}): Response {
  const status = init.status ?? 200;
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { "content-type": status >= 400 ? "application/problem+json" : "application/json", ...init.headers } });
}

export function problem(status: number, code: string, detail: string, extra: object = {}): Response {
  return json({ type: `https://agentshield.dev/errors/${code}`, title: code, status, code, detail, ...extra }, { status });
}

export type Handler = (url: URL, init: RequestInit) => Response | Promise<Response> | undefined;

/** Route fetch() calls to handlers keyed "METHOD /path". Unknown routes fail the test loudly. */
export function mockApi(routes: Record<string, Handler | Response | object>) {
  const calls: { method: string; path: string; body?: unknown; headers: Record<string, string> }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const key = `${method} ${url.pathname}`;
    calls.push({ method, path: url.pathname + url.search, body: init.body ? JSON.parse(String(init.body)) : undefined, headers: (init.headers ?? {}) as Record<string, string> });
    const h = routes[key];
    if (h === undefined) throw new Error(`unexpected request ${key}`);
    if (h instanceof Response) return h.clone();
    if (typeof h === "function") { const r = await h(url, init); if (r) return r; throw new Error(`handler for ${key} returned nothing`); }
    return json(h);
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export const ME = { user_id: "u1", tenant_id: "t1", email: "ana@acme.com", role: "admin", csrf_token: "csrf-1" };

export function renderApp(ui: ReactElement, { path = "/", withSession = true }: { path?: string; withSession?: boolean } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0 } } });
  window.history.pushState({}, "", path);
  const tree = (
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <ToastProvider>{withSession ? <SessionProvider>{ui}</SessionProvider> : ui}</ToastProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
  return { client, ...render(tree) };
}
