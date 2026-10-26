import { describe, expect, it, vi } from "vitest";
import { ApiProblem, api, setCsrf, setUnauthorizedHandler, withQuery } from "./client";
import { loginUrl, safeNext } from "./session";
import { json, mockApi, problem } from "../test/helpers";

describe("api client", () => {
  it("maps a 412 problem to ApiProblem with its code", async () => {
    mockApi({ "POST /v1/x": problem(412, "precondition_failed", "The agent changed since you loaded it") });
    const err = await api("POST", "/v1/x", { body: {} }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiProblem);
    expect(err).toMatchObject({ status: 412, code: "precondition_failed", detail: "The agent changed since you loaded it" });
  });
  it("keeps validation errors with line numbers", async () => {
    mockApi({ "POST /v1/p": problem(422, "policy_invalid", "Line 14: unknown operator", { errors: [{ line: 14, path: "rules[1].when.op", message: "unknown operator" }] }) });
    const err = (await api("POST", "/v1/p", { body: {} }).catch((e) => e)) as ApiProblem;
    expect(err.errors[0]).toEqual({ line: 14, path: "rules[1].when.op", message: "unknown operator" });
  });
  it("sends the CSRF header on writes only, and JSON bodies", async () => {
    const { calls } = mockApi({ "GET /v1/a": { ok: 1 }, "POST /v1/a": { ok: 2 } });
    setCsrf("tok");
    await api("GET", "/v1/a");
    await api("POST", "/v1/a", { body: { x: 1 } });
    expect(calls[0].headers["X-CSRF-Token"]).toBeUndefined();
    expect(calls[1].headers["X-CSRF-Token"]).toBe("tok");
    expect(calls[1].body).toEqual({ x: 1 });
  });
  it("runs the 401 handler with the current path, except for quiet calls", async () => {
    mockApi({ "GET /v1/s": problem(401, "unauthenticated", "Sign in") });
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    window.history.pushState({}, "", "/approvals/abc");
    await api("GET", "/v1/s").catch(() => {});
    expect(handler).toHaveBeenCalledWith("/approvals/abc");
    handler.mockClear();
    await api("GET", "/v1/s", { quiet: true }).catch(() => {});
    expect(handler).not.toHaveBeenCalled();
    setUnauthorizedHandler(null);
  });
  it("turns a network failure into a readable problem", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")));
    const err = await api("GET", "/v1/a").catch((e) => e);
    expect(err).toMatchObject({ status: 0, code: "network" });
  });
  it("returns the ETag and handles 204", async () => {
    mockApi({ "GET /v1/e": json({ a: 1 }, { headers: { etag: '"v1"' } }), "DELETE /v1/e": new Response(null, { status: 204 }) });
    const { apiRaw } = await import("./client");
    expect((await apiRaw("GET", "/v1/e")).etag).toBe('"v1"');
    expect(await api("DELETE", "/v1/e")).toBeUndefined();
  });
  it("builds query strings without empty values", () => {
    expect(withQuery("/v1/e", { a: 1, b: "", c: undefined, d: null, e: "x y" })).toBe("/v1/e?a=1&e=x+y");
  });
});

describe("login redirect", () => {
  it("round-trips the path and refuses open redirects", () => {
    expect(loginUrl("/approvals/abc?x=1")).toBe("/login?next=%2Fapprovals%2Fabc%3Fx%3D1");
    expect(safeNext("/approvals/abc")).toBe("/approvals/abc");
    for (const bad of ["//evil.com", "https://evil.com", "javascript:alert(1)", "/login", null]) expect(safeNext(bad)).toBe("/");
  });
});
