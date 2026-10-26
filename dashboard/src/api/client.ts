import type { components } from "./schema";

export type Schemas = components["schemas"];

/** An RFC 9457 problem returned by the API (or a network failure shaped the same way). */
export class ApiProblem extends Error {
  status: number;
  code: string;
  detail: string;
  errors: { line?: number; path?: string; message: string }[];
  requestId?: string;
  constructor(status: number, code: string, detail: string, errors: ApiProblem["errors"] = [], requestId?: string) {
    super(detail || code);
    this.name = "ApiProblem";
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.errors = errors;
    this.requestId = requestId;
  }
}

let csrf = "";
let onUnauthorized: ((path: string) => void) | null = null;
export const setCsrf = (token: string | null | undefined) => { csrf = token ?? ""; };
export const setUnauthorizedHandler = (fn: ((path: string) => void) | null) => { onUnauthorized = fn; };

type Query = Record<string, string | number | boolean | null | undefined>;
export interface ApiOptions { body?: unknown; query?: Query; headers?: Record<string, string>; /** do not run the 401 handler */ quiet?: boolean }
export interface ApiResult<T> { data: T; etag: string | null; status: number }

export function withQuery(path: string, query?: Query): string {
  if (!query) return path;
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
  const s = qs.toString();
  return s ? `${path}${path.includes("?") ? "&" : "?"}${s}` : path;
}

export async function apiRaw<T>(method: string, path: string, opts: ApiOptions = {}): Promise<ApiResult<T>> {
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  let body: string | undefined;
  if (opts.body !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.body); }
  let res: Response;
  try {
    res = await fetch(withQuery(path, opts.query), { method, headers, body, credentials: "same-origin" });
  } catch {
    throw new ApiProblem(0, "network", "Could not reach the AgentShield API. Check your connection and try again.");
  }
  if (res.ok) {
    const text = res.status === 204 ? "" : await res.text();
    return { data: (text ? JSON.parse(text) : undefined) as T, etag: res.headers.get("etag"), status: res.status };
  }
  let p: Partial<{ code: string; detail: string; title: string; errors: ApiProblem["errors"]; request_id: string }> = {};
  try { p = await res.json(); } catch { /* not JSON */ }
  const problem = new ApiProblem(res.status, p.code ?? `http_${res.status}`, p.detail ?? p.title ?? res.statusText, p.errors ?? [], p.request_id);
  if (res.status === 401 && !opts.quiet && onUnauthorized) onUnauthorized(window.location.pathname + window.location.search);
  throw problem;
}

export async function api<T>(method: string, path: string, opts: ApiOptions = {}): Promise<T> {
  return (await apiRaw<T>(method, path, opts)).data;
}
export const get = <T>(path: string, query?: Query) => api<T>("GET", path, { query });
export const post = <T>(path: string, body?: unknown, headers?: Record<string, string>) => api<T>("POST", path, { body: body ?? {}, headers });
export const patch = <T>(path: string, body: unknown, headers?: Record<string, string>) => api<T>("PATCH", path, { body, headers });
export const del = <T>(path: string) => api<T>("DELETE", path);

export interface Page<T> { items: T[]; next_cursor?: string | null }
